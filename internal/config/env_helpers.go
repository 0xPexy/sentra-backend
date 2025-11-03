package config

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
)

var envOnce sync.Once

func ensureEnvLoaded() {
	envOnce.Do(func() {
		if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("warning: failed to load .env file: %v", err)
		}
	})
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

func durationEnvHours(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		var hrs int
		if _, err := fmt.Sscan(v, &hrs); err == nil && hrs > 0 {
			return time.Duration(hrs) * time.Hour
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
