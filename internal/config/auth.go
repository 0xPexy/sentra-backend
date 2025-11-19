package config

import "time"

type AuthConfig struct {
	JWTSecret     string
	JWTTTL        time.Duration
	SIWEDomain    string
	SIWEURI       string
	SIWEStatement string
	SIWEChainID   uint64
	NonceTTL      time.Duration
}

func loadAuth() AuthConfig {
	return AuthConfig{
		JWTSecret:     mustenv("JWT_SECRET"),
		JWTTTL:        durationEnvHours("JWT_TTL", 24*time.Hour),
		SIWEDomain:    getenv("SIWE_DOMAIN", getenv("SERVER_DOMAIN", "localhost")),
		SIWEURI:       getenv("SIWE_URI", ""),
		SIWEStatement: getenv("SIWE_STATEMENT", ""),
		SIWEChainID:   u64env("SIWE_CHAIN_ID", 0),
		NonceTTL:      durationEnvSeconds("SIWE_NONCE_TTL", 5*time.Minute),
	}
}
