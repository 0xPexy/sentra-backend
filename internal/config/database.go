package config

type DatabaseConfig struct {
	SQLiteDSN string
}

func loadDatabase() DatabaseConfig {
	return DatabaseConfig{
		SQLiteDSN: getenv("SQLITE_DSN", "./data/app.db"),
	}
}
