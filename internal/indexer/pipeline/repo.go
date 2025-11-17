package pipeline

import (
	"context"

	"github.com/0xPexy/sentra-backend/internal/store"
)

type Repo interface {
	GetLogCursor(ctx context.Context, chainID uint64, address string) (*store.LogCursor, error)
	UpsertLogCursor(ctx context.Context, cursor *store.LogCursor) error
	UpsertUserOperationEvent(ctx context.Context, event *store.UserOperationEvent) error
	UpsertUserOperationTrace(ctx context.Context, trace *store.UserOperationTrace) error
	UpsertUserOperationRevert(ctx context.Context, revert *store.UserOperationRevert) error
	UpsertAccountDeployment(ctx context.Context, dep *store.AccountDeployment) error
	UpsertSimpleAccountInitialization(ctx context.Context, init *store.SimpleAccountInitialization) error
	UpsertSponsorship(ctx context.Context, s *store.Sponsorship) error
	UpsertNFTToken(ctx context.Context, token *store.NFTToken) error
	ListUserOpsMissingCallData(ctx context.Context, chainID uint64, limit int) ([]store.UserOperationEvent, error)
	ListUserOpsMissingTrace(ctx context.Context, chainID uint64, limit int) ([]store.UserOperationEvent, error)
}

type StoreAdapter struct {
	repo *store.Repository
	sink EventSink
}

type EventSink interface {
	PublishUserOperation(event *store.UserOperationEvent)
}

func NewStoreAdapter(repo *store.Repository, sink EventSink) *StoreAdapter {
	return &StoreAdapter{repo: repo, sink: sink}
}

func (a *StoreAdapter) GetLogCursor(ctx context.Context, chainID uint64, address string) (*store.LogCursor, error) {
	return a.repo.GetLogCursor(ctx, chainID, address)
}

func (a *StoreAdapter) UpsertLogCursor(ctx context.Context, cursor *store.LogCursor) error {
	return a.repo.UpsertLogCursor(ctx, cursor)
}

func (a *StoreAdapter) UpsertUserOperationEvent(ctx context.Context, event *store.UserOperationEvent) error {
	if err := a.repo.UpsertUserOperationEvent(ctx, event); err != nil {
		return err
	}
	if a.sink != nil {
		clone := *event
		a.sink.PublishUserOperation(&clone)
	}
	return nil
}

func (a *StoreAdapter) UpsertUserOperationTrace(ctx context.Context, trace *store.UserOperationTrace) error {
	return a.repo.UpsertUserOperationTrace(ctx, trace)
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

func (a *StoreAdapter) UpsertNFTToken(ctx context.Context, token *store.NFTToken) error {
	return a.repo.UpsertNFTToken(ctx, token)
}

func (a *StoreAdapter) ListUserOpsMissingCallData(ctx context.Context, chainID uint64, limit int) ([]store.UserOperationEvent, error) {
	return a.repo.ListUserOpsMissingCallData(ctx, chainID, limit)
}

func (a *StoreAdapter) ListUserOpsMissingTrace(ctx context.Context, chainID uint64, limit int) ([]store.UserOperationEvent, error) {
	return a.repo.ListUserOpsMissingTrace(ctx, chainID, limit)
}
