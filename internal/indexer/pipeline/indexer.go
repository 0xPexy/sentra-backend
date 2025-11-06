package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/0xPexy/sentra-backend/internal/store"
	"github.com/ethereum/go-ethereum"
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

var errTraceUnsupported = errors.New("trace unsupported")

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
	if err := i.backfillCallMetadata(ctx); err != nil {
		i.logf("call metadata backfill failed: %v", err)
	}
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return i.runTraceBackfill(ctx)
	})

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
		mapping := make(map[string]struct{})
		for _, ev := range events {
			mapping[strings.ToLower(ev.UserOpHash)] = struct{}{}
		}
		for _, ev := range events {
			txHash := common.HexToHash(ev.TxHash)
			meta, err := i.decoder.callDec.extract(ctx, txHash, ev.UserOpHash)
			if err != nil {
				updated := ev
				updated.CallSelector = unknownSelector
				updated.CallGasLimit = "0"
				updated.VerificationGasLimit = "0"
				updated.PreVerificationGas = "0"
				updated.MaxFeePerGas = "0"
				updated.MaxPriorityFeePerGas = "0"
				updated.PaymasterVerificationGasLimit = "0"
				updated.PaymasterPostOpGasLimit = "0"
				if err := i.repo.UpsertUserOperationEvent(ctx, &updated); err != nil {
					i.logf("backfill persist failed: hash=%s err=%v", updated.UserOpHash, err)
				}
				if errors.Is(err, ethereum.NotFound) {
					i.logf("backfill metadata skipped (tx missing): hash=%s tx=%s", ev.UserOpHash, ev.TxHash)
				} else {
					i.logf("backfill metadata failed: hash=%s err=%v", ev.UserOpHash, err)
				}
				continue
			}
			updated := ev
			if meta != nil {
				if meta.target != "" {
					updated.Target = strings.ToLower(meta.target)
				}
				if meta.selector != "" {
					updated.CallSelector = strings.ToLower(meta.selector)
				} else {
					updated.CallSelector = unknownSelector
				}
				if meta.beneficiary != "" {
					updated.Beneficiary = meta.beneficiary
				}
				updated.CallGasLimit = bigString(meta.callGasLimit)
				updated.VerificationGasLimit = bigString(meta.verificationGasLimit)
				updated.PreVerificationGas = bigString(meta.preVerificationGas)
				updated.MaxFeePerGas = bigString(meta.maxFeePerGas)
				updated.MaxPriorityFeePerGas = bigString(meta.maxPriorityFeePerGas)
				updated.PaymasterVerificationGasLimit = bigString(meta.paymasterVerificationLimit)
				updated.PaymasterPostOpGasLimit = bigString(meta.paymasterPostOpLimit)
			} else {
				updated.CallSelector = unknownSelector
				updated.CallGasLimit = "0"
				updated.VerificationGasLimit = "0"
				updated.PreVerificationGas = "0"
				updated.MaxFeePerGas = "0"
				updated.MaxPriorityFeePerGas = "0"
				updated.PaymasterVerificationGasLimit = "0"
				updated.PaymasterPostOpGasLimit = "0"
			}
			i.logf("backfill storing userOp: hash=%s target=%s selector=%s", updated.UserOpHash, updated.Target, updated.CallSelector)
			if err := i.repo.UpsertUserOperationEvent(ctx, &updated); err != nil {
				i.logf("backfill persist failed: hash=%s err=%v", updated.UserOpHash, err)
			}
			if meta != nil && meta.selector != "" {
				delete(mapping, strings.ToLower(updated.UserOpHash))
			}
		}
		if len(mapping) > 0 {
			i.logf("backfill warning: missing hashes after extract: %v", mapping)
		}
	}
}

func (i *Indexer) runTraceBackfill(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		events, err := i.repo.ListUserOpsMissingTrace(ctx, i.cfg.ChainID, 20)
		if err != nil {
			i.logf("trace backfill: list error: %v", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(5 * time.Second):
			}
			continue
		}

		if len(events) == 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
			}
			continue
		}

		for _, ev := range events {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			if err := i.fetchAndStoreTrace(ctx, &ev); err != nil {
				if errors.Is(err, errTraceUnsupported) {
					i.logf("trace backfill disabled: %v", err)
					return nil
				}
				i.logf("trace backfill failed: hash=%s err=%v", ev.UserOpHash, err)
			}
		}
	}
}

func (i *Indexer) fetchAndStoreTrace(ctx context.Context, ev *store.UserOperationEvent) error {
	if ev == nil {
		return nil
	}
	if i.client == nil {
		return errTraceUnsupported
	}
	res, err := i.client.TraceTransaction(ctx, common.HexToHash(ev.TxHash))
	if err != nil {
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "method not found") || strings.Contains(errStr, "does not exist") || strings.Contains(errStr, "unsupported method") {
			return errTraceUnsupported
		}
		return err
	}
	summary := summarizeTrace(res, ev, i.cfg.EntryPoint)
	if len(summary.Phases) == 0 {
		summary.Phases = []PhaseGas{}
	}
	data, err := json.Marshal(summary.Phases)
	if err != nil {
		return err
	}
	trace := &store.UserOperationTrace{
		ChainID:      i.cfg.ChainID,
		UserOpHash:   strings.ToLower(ev.UserOpHash),
		TxHash:       strings.ToLower(ev.TxHash),
		TraceSummary: string(data),
	}
	if err := i.repo.UpsertUserOperationTrace(ctx, trace); err != nil {
		return err
	}
	updated := *ev
	needsUpdate := false
	if summary.CallGasLimit != "" && summary.CallGasLimit != ev.CallGasLimit {
		updated.CallGasLimit = summary.CallGasLimit
		needsUpdate = true
	}
	if summary.VerificationGasLimit != "" && summary.VerificationGasLimit != ev.VerificationGasLimit {
		updated.VerificationGasLimit = summary.VerificationGasLimit
		needsUpdate = true
	}
	if summary.PaymasterVerificationGasLimit != "" && summary.PaymasterVerificationGasLimit != ev.PaymasterVerificationGasLimit {
		updated.PaymasterVerificationGasLimit = summary.PaymasterVerificationGasLimit
		needsUpdate = true
	}
	if summary.PaymasterPostOpGasLimit != "" && summary.PaymasterPostOpGasLimit != ev.PaymasterPostOpGasLimit {
		updated.PaymasterPostOpGasLimit = summary.PaymasterPostOpGasLimit
		needsUpdate = true
	}
	if summary.PreVerificationGas != "" && summary.PreVerificationGas != ev.PreVerificationGas {
		updated.PreVerificationGas = summary.PreVerificationGas
		needsUpdate = true
	}
	if summary.MaxFeePerGas != "" && summary.MaxFeePerGas != ev.MaxFeePerGas {
		updated.MaxFeePerGas = summary.MaxFeePerGas
		needsUpdate = true
	}
	if summary.MaxPriorityFeePerGas != "" && summary.MaxPriorityFeePerGas != ev.MaxPriorityFeePerGas {
		updated.MaxPriorityFeePerGas = summary.MaxPriorityFeePerGas
		needsUpdate = true
	}
	if needsUpdate {
		if err := i.repo.UpsertUserOperationEvent(ctx, &updated); err != nil {
			i.logf("trace backfill: failed to refresh event gas fields: hash=%s err=%v", ev.UserOpHash, err)
		}
	}
	i.logf("trace stored: hash=%s phases=%d", ev.UserOpHash, len(summary.Phases))
	return nil
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
