package pipeline

import (
	"time"

	"github.com/ethereum/go-ethereum/common"
)

type Config struct {
	ChainID                 uint64
	EntryPoint              common.Address
	ERC721                  common.Address
	Paymaster               *common.Address
	DeploymentBlock         uint64
	ChunkSize               uint64
	Confirmations           uint64
	PollInterval            time.Duration
	DecodeWorkerCount       int
	WriteWorkerCount        int
	ResubscribeDelay        time.Duration
	MaxFilterRange          uint64
	AllowNoPaymasterAddress bool
}

func (c Config) chunkSize() uint64 {
	if c.ChunkSize == 0 {
		return 2_000
	}
	return c.ChunkSize
}

func (c Config) confirmations() uint64 {
	return c.Confirmations
}

func (c Config) decodeWorkerCount() int {
	if c.DecodeWorkerCount <= 0 {
		return 4
	}
	return c.DecodeWorkerCount
}

func (c Config) writeWorkerCount() int {
	if c.WriteWorkerCount <= 0 {
		return 2
	}
	return c.WriteWorkerCount
}

func (c Config) pollInterval() time.Duration {
	if c.PollInterval <= 0 {
		return 15 * time.Second
	}
	return c.PollInterval
}

func (c Config) resubscribeDelay() time.Duration {
	if c.ResubscribeDelay <= 0 {
		return 5 * time.Second
	}
	return c.ResubscribeDelay
}

func (c Config) filterRangeLimit() uint64 {
	if c.MaxFilterRange == 0 {
		return c.chunkSize()
	}
	return c.MaxFilterRange
}
