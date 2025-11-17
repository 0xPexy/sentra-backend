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
	"github.com/ethereum/go-ethereum/rpc"
)

type combinedEventSink struct {
	sinks []pipeline.EventSink
}

func newCombinedSink(sinks ...pipeline.EventSink) pipeline.EventSink {
	valid := make([]pipeline.EventSink, 0, len(sinks))
	for _, s := range sinks {
		if s != nil {
			valid = append(valid, s)
		}
	}
	if len(valid) == 0 {
		return nil
	}
	if len(valid) == 1 {
		return valid[0]
	}
	return &combinedEventSink{sinks: valid}
}

func (c *combinedEventSink) PublishUserOperation(event *store.UserOperationEvent) {
	for _, sink := range c.sinks {
		if sink != nil {
			sink.PublishUserOperation(event)
		}
	}
}

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
	playgroundHub := server.NewPlaygroundHub(log.New(log.Writer(), "playground: ", log.LstdFlags))
	indexerReader := indexersvc.NewReader(repo)
	authSvc := auth.NewService(cfg.Auth.JWTSecret, repo, cfg.Auth.JWTTTL, cfg.Auth.DevToken)
	if cfg.Auth.DevToken != "" {
		store.EnsureDevAdmin(db, auth.DevAdminID(), cfg.Auth.DevAdminUser)
	}
	policy := erc7677.NewPolicy(repo, cfg)
	rpcClient, err := rpc.Dial(cfg.Chain.RPCURL)
	if err != nil {
		log.Fatalf("failed to connect chain rpc: %v", err)
	}

	ethClient := ethclient.NewClient(rpcClient)
	defer ethClient.Close()

	traceClient, err := pipeline.NewTraceableEthClient(ethClient, rpcClient)
	if err != nil {
		log.Fatalf("failed to create traceable client: %v", err)
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
		var nftAddr common.Address
		if cfg.Chain.ERC721Address != "" {
			nftAddr = common.HexToAddress(cfg.Chain.ERC721Address)
		}
		idxCfg := pipeline.Config{
			ChainID:           chainID.Uint64(),
			EntryPoint:        entryPointAddr,
			ERC721:            nftAddr,
			Paymaster:         paymasterAddrPtr,
			DeploymentBlock:   cfg.Chain.EntryPointDeployBlock,
			ChunkSize:         cfg.Indexer.ChunkSize,
			Confirmations:     cfg.Indexer.Confirmations,
			PollInterval:      cfg.Indexer.PollInterval,
			DecodeWorkerCount: cfg.Indexer.DecodeWorkers,
			WriteWorkerCount:  cfg.Indexer.WriteWorkers,
		}
		sink := newCombinedSink(eventHub, playgroundHub)
		sentraIndexer = pipeline.New(idxCfg, pipeline.NewStoreAdapter(repo, sink), traceClient, log.New(log.Writer(), "indexer: ", log.LstdFlags))
	}

	pmLogger := log.New(log.Writer(), "pm: ", log.LstdFlags)
	pm := erc7677.NewHandler(cfg, repo, policy, signer, ethClient, pmLogger)
	adminH := admin.NewHandler(authSvc, repo, cfg)

	r := server.NewRouter(cfg, authSvc, pm, adminH, repo, indexerReader, eventHub, playgroundHub)
	srv := server.NewHTTP(cfg.Server.HTTPAddr, r)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go eventHub.Run(ctx)
	if playgroundHub != nil {
		go playgroundHub.Run(ctx)
	}
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
