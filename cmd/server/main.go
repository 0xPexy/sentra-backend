package main

import (
	"context"
	"errors"
	"log"
	"os/signal"
	"syscall"
	"time"

	docs "github.com/0xPexy/sentra-backend/docs"
	"github.com/0xPexy/sentra-backend/internal/admin"
	"github.com/0xPexy/sentra-backend/internal/auth"
	cfgpkg "github.com/0xPexy/sentra-backend/internal/config"
	"github.com/0xPexy/sentra-backend/internal/erc7677"
	pipeline "github.com/0xPexy/sentra-backend/internal/indexer/pipeline"
	indexersvc "github.com/0xPexy/sentra-backend/internal/indexer/service"
	"github.com/0xPexy/sentra-backend/internal/server"
	"github.com/0xPexy/sentra-backend/internal/store"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// @title Sentinel 4337 Backend API
// @version 1.0
// @description API documentation for the Sentinel 4337 backend service.
// @BasePath /
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {
	cfg := cfgpkg.Load()
	docs.SwaggerInfo.Version = "1.0"
	docs.SwaggerInfo.Title = "Sentinel 4337 Backend API"
	docs.SwaggerInfo.Description = "API documentation for the Sentinel 4337 backend service."
	docs.SwaggerInfo.BasePath = "/"

	db := store.OpenSQLite(cfg.Database.SQLiteDSN)
	store.AutoMigrate(db)
	store.EnsureAdmin(db, cfg.Admin.Username, cfg.Admin.Password)

	repo := store.NewRepository(db)
	eventHub := server.NewEventHub(log.New(log.Writer(), "events: ", log.LstdFlags))
	indexerReader := indexersvc.NewReader(repo)
	authSvc := auth.NewService(cfg.Auth.JWTSecret, repo, cfg.Auth.JWTTTL, cfg.Auth.DevToken)
	if cfg.Auth.DevToken != "" {
		store.EnsureDevAdmin(db, auth.DevAdminID(), cfg.Auth.DevAdminUser)
	}
	policy := erc7677.NewPolicy(repo, cfg)
	ethClient, err := ethclient.Dial(cfg.Chain.RPCURL)
	if err != nil {
		log.Fatalf("failed to connect chain rpc: %v", err)
	}
	chainID, err := ethClient.ChainID(context.Background())
	if err != nil {
		log.Fatalf("failed to get chain id: %v", err)
	}
	signer := erc7677.NewSigner(cfg.Paymaster.PolicyPrivateKey, chainID)

	var sentraIndexer *pipeline.Indexer
	if cfg.Indexer.Enabled {
		entryPointAddr := common.HexToAddress(cfg.Chain.EntryPoint)
		var paymasterAddrPtr *common.Address
		if cfg.Paymaster.Address != "" {
			addr := common.HexToAddress(cfg.Paymaster.Address)
			paymasterAddrPtr = &addr
		}
		idxCfg := pipeline.Config{
			ChainID:           chainID.Uint64(),
			EntryPoint:        entryPointAddr,
			Paymaster:         paymasterAddrPtr,
			DeploymentBlock:   cfg.Chain.EntryPointDeployBlock,
			ChunkSize:         cfg.Indexer.ChunkSize,
			Confirmations:     cfg.Indexer.Confirmations,
			PollInterval:      cfg.Indexer.PollInterval,
			DecodeWorkerCount: cfg.Indexer.DecodeWorkers,
			WriteWorkerCount:  cfg.Indexer.WriteWorkers,
		}
		sentraIndexer = pipeline.New(idxCfg, pipeline.NewStoreAdapter(repo, eventHub), ethClient, log.New(log.Writer(), "indexer: ", log.LstdFlags))
	}

	pmLogger := log.New(log.Writer(), "pm: ", log.LstdFlags)
	pm := erc7677.NewHandler(cfg, repo, policy, signer, ethClient, pmLogger)
	adminH := admin.NewHandler(authSvc, repo, cfg)

	r := server.NewRouter(cfg, authSvc, pm, adminH, repo, indexerReader, eventHub)
	srv := server.NewHTTP(cfg.Server.HTTPAddr, r)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go eventHub.Run(ctx)
	if sentraIndexer != nil {
		go func() {
			if err := sentraIndexer.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("indexer stopped: %v", err)
			}
		}()
	}
	go func() {
		if err := srv.Start(); err != nil {
			log.Fatal(err)
		}
	}()
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Stop(shutdown)
}
