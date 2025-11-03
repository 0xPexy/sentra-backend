package config

type Config struct {
	Server    ServerConfig
	Database  DatabaseConfig
	Auth      AuthConfig
	Admin     AdminConfig
	Chain     ChainConfig
	Paymaster PaymasterConfig
	Indexer   IndexerConfig
}

func Load() Config {
	ensureEnvLoaded()
	return Config{
		Server:    loadServer(),
		Database:  loadDatabase(),
		Auth:      loadAuth(),
		Admin:     loadAdmin(),
		Chain:     loadChain(),
		Paymaster: loadPaymaster(),
		Indexer:   loadIndexer(),
	}
}
