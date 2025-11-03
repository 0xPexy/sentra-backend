package config

import "time"

type AuthConfig struct {
	JWTSecret    string
	JWTTTL       time.Duration
	DevToken     string
	DevAdminUser string
}

func loadAuth() AuthConfig {
	return AuthConfig{
		JWTSecret:    mustenv("JWT_SECRET"),
		JWTTTL:       durationEnvHours("JWT_TTL", 24*time.Hour),
		DevToken:     getenv("DEV_TOKEN", ""),
		DevAdminUser: getenv("DEV_ADMIN_USERNAME", "dev-token"),
	}
}
