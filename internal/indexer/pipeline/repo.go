package pipeline

import (
	"context"

	"github.com/0xPexy/sentra-backend/internal/store"
)

type Repo interface {
	GetLogCursor(ctx context.Context, chainID uint64, address string) (*store.LogCursor, error)
	UpsertLogCursor(ctx context.Context, cursor *store.LogCursor) error
	UpsertUserOperationEvent(ctx context.Context, event *store.UserOperationEvent) error
	UpsertUserOperationRevert(ctx context.Context, revert *store.UserOperationRevert) error
	UpsertAccountDeployment(ctx context.Context, dep *store.AccountDeployment) error
	UpsertSimpleAccountInitialization(ctx context.Context, init *store.SimpleAccountInitialization) error
	UpsertSponsorship(ctx context.Context, s *store.Sponsorship) error
}

type StoreAdapter struct {
	repo *store.Repository
}

func NewStoreAdapter(repo *store.Repository) *StoreAdapter {
	return &StoreAdapter{repo: repo}
}

func (a *StoreAdapter) GetLogCursor(ctx context.Context, chainID uint64, address string) (*store.LogCursor, error) {
	return a.repo.GetLogCursor(ctx, chainID, address)
}

func (a *StoreAdapter) UpsertLogCursor(ctx context.Context, cursor *store.LogCursor) error {
	return a.repo.UpsertLogCursor(ctx, cursor)
}

func (a *StoreAdapter) UpsertUserOperationEvent(ctx context.Context, event *store.UserOperationEvent) error {
	return a.repo.UpsertUserOperationEvent(ctx, event)
}

func (a *StoreAdapter) UpsertUserOperationRevert(ctx context.Context, revert *store.UserOperationRevert) error {
	return a.repo.UpsertUserOperationRevert(ctx, revert)
}

func (a *StoreAdapter) UpsertAccountDeployment(ctx context.Context, dep *store.AccountDeployment) error {
	return a.repo.UpsertAccountDeployment(ctx, dep)
}

func (a *StoreAdapter) UpsertSimpleAccountInitialization(ctx context.Context, init *store.SimpleAccountInitialization) error {
	return a.repo.UpsertSimpleAccountInitialization(ctx, init)
}

func (a *StoreAdapter) UpsertSponsorship(ctx context.Context, s *store.Sponsorship) error {
	return a.repo.UpsertSponsorship(ctx, s)
}
