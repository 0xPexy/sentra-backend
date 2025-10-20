package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"
	"time"

	"github.com/0xPexy/sentra-backend/internal/admin"
	"github.com/0xPexy/sentra-backend/internal/auth"
	cfgpkg "github.com/0xPexy/sentra-backend/internal/config"
	"github.com/0xPexy/sentra-backend/internal/erc7677"
	"github.com/0xPexy/sentra-backend/internal/server"
	"github.com/0xPexy/sentra-backend/internal/store"
)

func main() {
	cfg := cfgpkg.Load()

	db := store.OpenSQLite(cfg.SQLiteDSN)
	store.AutoMigrate(db)
	store.EnsureAdmin(db, cfg.AdminUsername, cfg.AdminPassword)

	repo := store.NewRepository(db)
	authSvc := auth.NewService(cfg.JWTSecret, repo, cfg.JWTTTL, cfg.DevToken)
	if cfg.DevToken != "" {
		store.EnsureDevAdmin(db, auth.DevAdminID(), cfg.DevAdminUser)
	}
	policy := erc7677.NewPolicy(repo, cfg)
	signer := erc7677.NewSigner(cfg.PolicySK)
	pm := erc7677.NewHandler(cfg, policy, signer)
	adminH := admin.NewHandler(authSvc, repo, cfg)

	r := server.NewRouter(cfg, authSvc, pm, adminH)
	srv := server.NewHTTP(cfg.HTTPAddr, r)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
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
