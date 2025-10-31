package pipeline

import (
	"context"
	"errors"
	"log"
	"math/big"
	"time"

	"github.com/0xPexy/sentra-backend/internal/store"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

type logSubscriber struct {
	cfg    Config
	repo   Repo
	client EthClient
	topics []common.Hash
	logger *log.Logger
}

func newLogSubscriber(cfg Config, repo Repo, client EthClient, topics []common.Hash, logger *log.Logger) *logSubscriber {
	return &logSubscriber{
		cfg:    cfg,
		repo:   repo,
		client: client,
		topics: topics,
		logger: logger,
	}
}

func (s *logSubscriber) stream(ctx context.Context, out chan<- types.Log) error {
	entryPointAddr := s.cfg.EntryPoint.Hex()
	cursor, err := s.repo.GetLogCursor(ctx, s.cfg.ChainID, entryPointAddr)
	if err != nil {
		return err
	}
	var lastProcessed uint64
	var lastTxHash string
	var lastLogIndex uint
	if cursor != nil {
		lastProcessed = cursor.LastBlock
		lastTxHash = cursor.LastTxHash
		lastLogIndex = cursor.LastLogIndex
		s.logf("Cursor restored: lastBlock=%d lastTx=%s lastLogIndex=%d", lastProcessed, lastTxHash, lastLogIndex)
	}
	startBlock := s.cfg.DeploymentBlock
	if lastProcessed > 0 && lastProcessed >= startBlock {
		startBlock = lastProcessed + 1
	}
	if startBlock == 0 && s.cfg.DeploymentBlock > 0 {
		startBlock = s.cfg.DeploymentBlock
	}

	chunkSize := s.cfg.chunkSize()
	confirmations := s.cfg.confirmations()
	pollInterval := s.cfg.pollInterval()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		head, err := s.client.HeaderByNumber(ctx, nil)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			s.logf("indexer: failed to fetch head: %v", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(s.cfg.resubscribeDelay()):
			}
			continue
		}
		var safeHead uint64
		if head.Number == nil {
			safeHead = 0
		} else {
			headNumber := head.Number.Uint64()
			if headNumber > confirmations {
				safeHead = headNumber - confirmations
			} else {
				safeHead = 0
			}
		}

		if safeHead < startBlock {
			s.logf("Waiting for safe head: startBlock=%d safeHead=%d", startBlock, safeHead)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(pollInterval):
				continue
			}
		}

		from := startBlock
		for from <= safeHead {
			to := from + chunkSize - 1
			if to > safeHead {
				to = safeHead
			}
			s.logf("Fetching logs: from=%d to=%d safeHead=%d", from, to, safeHead)

			query := ethereum.FilterQuery{
				FromBlock: new(big.Int).SetUint64(from),
				ToBlock:   new(big.Int).SetUint64(to),
				Topics:    [][]common.Hash{s.topics},
			}

			logs, err := s.client.FilterLogs(ctx, query)
			if err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return err
				}
				s.logf("indexer: filter logs %d-%d failed: %v", from, to, err)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(s.cfg.resubscribeDelay()):
				}
				break
			}

			filtered := make([]types.Log, 0, len(logs))
			for _, lg := range logs {
				if len(lg.Topics) == 0 {
					continue
				}
				if !s.handlesTopic(lg.Topics[0]) {
					continue
				}
				filtered = append(filtered, lg)
			}
			s.logf("Fetched logs: from=%d to=%d total=%d matched=%d", from, to, len(logs), len(filtered))

			for _, lg := range filtered {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case out <- lg:
				}
				lastTxHash = lg.TxHash.Hex()
				lastLogIndex = uint(lg.Index)
				lastProcessed = lg.BlockNumber
			}

			if len(filtered) == 0 && lastProcessed < to {
				lastProcessed = to
			}

			if err := s.repo.UpsertLogCursor(ctx, &store.LogCursor{
				ChainID:      s.cfg.ChainID,
				Address:      entryPointAddr,
				LastBlock:    max64(lastProcessed, to),
				LastTxHash:   lastTxHash,
				LastLogIndex: lastLogIndex,
			}); err != nil {
				return err
			}
			s.logf("Cursor updated: lastBlock=%d lastTx=%s lastLogIndex=%d", max64(lastProcessed, to), lastTxHash, lastLogIndex)

			from = to + 1
			startBlock = from
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

func (s *logSubscriber) handlesTopic(topic common.Hash) bool {
	for _, t := range s.topics {
		if t == topic {
			return true
		}
	}
	return false
}

func (s *logSubscriber) logf(format string, args ...any) {
	if s.logger != nil {
		s.logger.Printf(format, args...)
	}
}

func max64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
