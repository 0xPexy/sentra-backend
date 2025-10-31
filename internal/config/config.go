package config

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	HTTPAddr              string
	SQLiteDSN             string
	JWTSecret             string
	JWTTTL                time.Duration
	DevToken              string
	DevAdminUser          string
	ChainRPCURL           string
	EntryPoint            string
	EntryPointDeployBlock uint64
	DefaultUSDPer         int64
	PolicySK              string
	PMValGas              uint64
	PostOpGas             uint64
	PaymasterAddr         string
	AdminUsername         string
	AdminPassword         string
	IndexerEnabled        bool
	IndexerChunkSize      uint64
	IndexerConfirmations  uint64
	IndexerPollInterval   time.Duration
	IndexerDecodeWorker   int
	IndexerWriteWorker    int
}

func init() {
	// Dev convenience: load .env if present
	_ = godotenv.Load()
}

func Load() Config {
	return Config{
		HTTPAddr:              getenv("HTTP_ADDR", ":8080"),
		SQLiteDSN:             getenv("SQLITE_DSN", "./data/app.db"),
		JWTSecret:             mustenv("JWT_SECRET"),
		JWTTTL:                durationEnv("JWT_TTL", 24*time.Hour),
		DevToken:              getenv("DEV_TOKEN", ""),
		DevAdminUser:          getenv("DEV_ADMIN_USERNAME", "dev-token"),
		ChainRPCURL:           getenv("CHAIN_RPC_URL", ""),
		EntryPoint:            mustenv("ENTRY_POINT"),
		EntryPointDeployBlock: u64env("ENTRY_POINT_DEPLOY_BLOCK", 0),
		DefaultUSDPer:         i64env("USD_PER_MAX_OP_DEFAULT", 1),
		PolicySK:              mustenv("POLICY_SIGNER_PK"),
		PMValGas:              u64env("PM_VALIDATION_GAS", 120_000),
		PostOpGas:             u64env("PM_POSTOP_GAS", 80_000),
		PaymasterAddr:         mustenv("PAYMASTER_ADDRESS"),
		AdminUsername:         getenv("ADMIN_USERNAME", "admin"),
		AdminPassword:         getenv("ADMIN_PASSWORD", "admin123"),
		IndexerEnabled:        boolenv("INDEXER_ENABLED", true),
		IndexerChunkSize:      u64env("INDEXER_CHUNK_SIZE", 2_000),
		IndexerConfirmations:  u64env("INDEXER_CONFIRMATIONS", 0),
		IndexerPollInterval:   durationEnvSeconds("INDEXER_POLL_INTERVAL", 15*time.Second),
		IndexerDecodeWorker:   intEnv("INDEXER_DECODE_WORKERS", 4),
		IndexerWriteWorker:    intEnv("INDEXER_WRITE_WORKERS", 2),
	}
}

func getenv(k, def string) string {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	return v
}
func mustenv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("missing %s", k)
	}
	return v
}
func u64env(k string, def uint64) uint64 {
	if v := os.Getenv(k); v != "" {
		var x uint64
		_, _ = fmt.Sscan(v, &x)
		if x > 0 {
			return x
		}
	}
	return def
}

func durationEnv(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		var hrs int
		if _, err := fmt.Sscan(v, &hrs); err == nil && hrs > 0 {
			return time.Duration(hrs) * time.Hour
		}
	}
	return def
}

func i64env(k string, def int64) int64 {
	if v := os.Getenv(k); v != "" {
		var x int64
		if _, err := fmt.Sscan(v, &x); err == nil {
			return x
		}
	}
	return def
}

func boolenv(k string, def bool) bool {
	if v := os.Getenv(k); v != "" {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "yes", "y", "on":
			return true
		case "0", "false", "no", "n", "off":
			return false
		}
	}
	return def
}

func intEnv(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		var x int
		if _, err := fmt.Sscan(v, &x); err == nil && x > 0 {
			return x
		}
	}
	return def
}

func durationEnvSeconds(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if dur, err := time.ParseDuration(v); err == nil {
			return dur
		}
		var secs int
		if _, err := fmt.Sscan(v, &secs); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return def
}
