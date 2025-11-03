package pipeline

import (
	"context"
	"log"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"golang.org/x/sync/errgroup"
)

type Indexer struct {
	cfg        Config
	repo       Repo
	client     EthClient
	logger     *log.Logger
	decoder    *decoder
	subscriber *logSubscriber
}

func New(cfg Config, repo Repo, client EthClient, logger *log.Logger) *Indexer {
	if logger == nil {
		logger = log.Default()
	}
	d := newDecoder(cfg, client, logger)
	sub := newLogSubscriber(cfg, repo, client, d.topicsList(), logger)
	return &Indexer{
		cfg:        cfg,
		repo:       repo,
		client:     client,
		logger:     logger,
		decoder:    d,
		subscriber: sub,
	}
}

func (i *Indexer) Run(ctx context.Context) error {
	i.logf("Indexer starting: chain=%d entryPoint=%s", i.cfg.ChainID, i.cfg.EntryPoint.Hex())
	// Temporarily disabled call metadata backfill; re-enable once decoder handles all EntryPoint variants.
	g, ctx := errgroup.WithContext(ctx)

	decodeCh := make(chan types.Log, i.cfg.decodeWorkerCount()*32)
	writeCh := make(chan writeRequest, i.cfg.writeWorkerCount()*16)

	g.Go(func() error {
		defer close(decodeCh)
		return i.subscriber.stream(ctx, decodeCh)
	})

	var decodeWG sync.WaitGroup
	for n := 0; n < i.cfg.decodeWorkerCount(); n++ {
		decodeWG.Add(1)
		g.Go(func() error {
			defer decodeWG.Done()
			return i.runDecodeWorker(ctx, decodeCh, writeCh)
		})
	}

	g.Go(func() error {
		decodeWG.Wait()
		close(writeCh)
		return nil
	})

	for n := 0; n < i.cfg.writeWorkerCount(); n++ {
		g.Go(func() error {
			return i.runWriteWorker(ctx, writeCh)
		})
	}

	err := g.Wait()
	if err != nil {
		i.logf("Indexer stopped with error: %v", err)
		return err
	}
	i.logf("Indexer stopped cleanly")
	return nil
}

func (i *Indexer) runDecodeWorker(ctx context.Context, in <-chan types.Log, out chan<- writeRequest) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case lg, ok := <-in:
			if !ok {
				return nil
			}
			reqs, err := i.decoder.decode(ctx, lg)
			if err != nil {
				i.logf("decoder error: block=%d tx=%s index=%d err=%v", lg.BlockNumber, lg.TxHash.Hex(), lg.Index, err)
				return err
			}
			for _, req := range reqs {
				if req.apply == nil {
					continue
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case out <- req:
				}
			}
		}
	}
}

func (i *Indexer) runWriteWorker(ctx context.Context, in <-chan writeRequest) error {
	for req := range in {
		if req.apply == nil {
			continue
		}
		callCtx := ctx
		if err := callCtx.Err(); err != nil {
			callCtx = context.Background()
		}
		i.logf("persisting %s", req.name)
		if err := req.apply(callCtx, i.repo); err != nil {
			i.logf("database write error (%s): %v", req.name, err)
			return err
		}
		i.logf("persisted %s", req.name)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (i *Indexer) backfillCallMetadata(ctx context.Context) error {
	if i.decoder == nil || i.decoder.callDec == nil {
		return nil
	}
	for {
		events, err := i.repo.ListUserOpsMissingCallData(ctx, i.cfg.ChainID, 100)
		if err != nil {
			return err
		}
		if len(events) == 0 {
			return nil
		}
		for _, ev := range events {
			txHash := common.HexToHash(ev.TxHash)
			target, selector, err := i.decoder.callDec.extract(ctx, txHash, ev.UserOpHash)
			if err != nil {
				i.logf("backfill metadata failed: hash=%s err=%v", ev.UserOpHash, err)
				continue
			}
			if target == "" && selector == "" {
				continue
			}
			updated := ev
			if target != "" {
				updated.Target = target
			}
			if selector != "" {
				updated.CallSelector = selector
			}
			if err := i.repo.UpsertUserOperationEvent(ctx, &updated); err != nil {
				i.logf("backfill persist failed: hash=%s err=%v", updated.UserOpHash, err)
			}
		}
	}
}

type writeRequest struct {
	name  string
	apply func(context.Context, Repo) error
}

func (i *Indexer) logf(format string, args ...any) {
	if i.logger != nil {
		i.logger.Printf(format, args...)
	}
}
