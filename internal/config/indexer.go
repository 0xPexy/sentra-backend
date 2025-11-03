package config

import "time"

type IndexerConfig struct {
	Enabled       bool
	ChunkSize     uint64
	Confirmations uint64
	PollInterval  time.Duration
	DecodeWorkers int
	WriteWorkers  int
}

func loadIndexer() IndexerConfig {
	return IndexerConfig{
		Enabled:       boolenv("INDEXER_ENABLED", true),
		ChunkSize:     u64env("INDEXER_CHUNK_SIZE", 2_000),
		Confirmations: u64env("INDEXER_CONFIRMATIONS", 0),
		PollInterval:  durationEnvSeconds("INDEXER_POLL_INTERVAL", 15*time.Second),
		DecodeWorkers: intEnv("INDEXER_DECODE_WORKERS", 4),
		WriteWorkers:  intEnv("INDEXER_WRITE_WORKERS", 2),
	}
}
