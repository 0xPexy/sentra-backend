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
	"github.com/0xPexy/sentra-backend/internal/server"
	"github.com/0xPexy/sentra-backend/internal/store"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// @title Sentinel 4337 Backend API
// @version 1.0
// @description API documentation for the Sentinel 4337 backend service.
// @BasePath /api/v1
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {
	cfg := cfgpkg.Load()
	docs.SwaggerInfo.Version = "1.0"
	docs.SwaggerInfo.Title = "Sentinel 4337 Backend API"
	docs.SwaggerInfo.Description = "API documentation for the Sentinel 4337 backend service."
	docs.SwaggerInfo.BasePath = "/api/v1"

	db := store.OpenSQLite(cfg.SQLiteDSN)
	store.AutoMigrate(db)
	store.EnsureAdmin(db, cfg.AdminUsername, cfg.AdminPassword)

	repo := store.NewRepository(db)
	authSvc := auth.NewService(cfg.JWTSecret, repo, cfg.JWTTTL, cfg.DevToken)
	if cfg.DevToken != "" {
		store.EnsureDevAdmin(db, auth.DevAdminID(), cfg.DevAdminUser)
	}
	policy := erc7677.NewPolicy(repo, cfg)
	ethClient, err := ethclient.Dial(cfg.ChainRPCURL)
	if err != nil {
		log.Fatalf("failed to connect chain rpc: %v", err)
	}
	chainID, err := ethClient.ChainID(context.Background())
	if err != nil {
		log.Fatalf("failed to get chain id: %v", err)
	}
	signer := erc7677.NewSigner(cfg.PolicySK, chainID)

	var sentraIndexer *pipeline.Indexer
	if cfg.IndexerEnabled {
		entryPointAddr := common.HexToAddress(cfg.EntryPoint)
		var paymasterAddrPtr *common.Address
		if cfg.PaymasterAddr != "" {
			addr := common.HexToAddress(cfg.PaymasterAddr)
			paymasterAddrPtr = &addr
		}
		idxCfg := pipeline.Config{
			ChainID:           chainID.Uint64(),
			EntryPoint:        entryPointAddr,
			Paymaster:         paymasterAddrPtr,
			DeploymentBlock:   cfg.EntryPointDeployBlock,
			ChunkSize:         cfg.IndexerChunkSize,
			Confirmations:     cfg.IndexerConfirmations,
			PollInterval:      cfg.IndexerPollInterval,
			DecodeWorkerCount: cfg.IndexerDecodeWorker,
			WriteWorkerCount:  cfg.IndexerWriteWorker,
		}
		sentraIndexer = pipeline.New(idxCfg, pipeline.NewStoreAdapter(repo), ethClient, log.New(log.Writer(), "indexer: ", log.LstdFlags))
	}

	pmLogger := log.New(log.Writer(), "pm: ", log.LstdFlags)
	pm := erc7677.NewHandler(cfg, repo, policy, signer, ethClient, pmLogger)
	adminH := admin.NewHandler(authSvc, repo, cfg)

	r := server.NewRouter(cfg, authSvc, pm, adminH)
	srv := server.NewHTTP(cfg.HTTPAddr, r)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
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
