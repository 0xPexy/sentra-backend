package pipeline

import (
	"context"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/core/types"
)

type EthClient interface {
	FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error)
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
}

type blockTimeCache struct {
	client EthClient
	mu     sync.Mutex
	cache  map[uint64]time.Time
}

func newBlockTimeCache(client EthClient) *blockTimeCache {
	return &blockTimeCache{
		client: client,
		cache:  make(map[uint64]time.Time),
	}
}

func (b *blockTimeCache) Time(ctx context.Context, blockNumber uint64) (time.Time, error) {
	b.mu.Lock()
	if ts, ok := b.cache[blockNumber]; ok {
		b.mu.Unlock()
		return ts, nil
	}
	b.mu.Unlock()

	header, err := b.client.HeaderByNumber(ctx, new(big.Int).SetUint64(blockNumber))
	if err != nil {
		return time.Time{}, err
	}
	ts := time.Unix(int64(header.Time), 0)

	b.mu.Lock()
	b.cache[blockNumber] = ts
	b.mu.Unlock()

	return ts, nil
}
