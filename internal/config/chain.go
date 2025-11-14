package config

type ChainConfig struct {
	RPCURL                string
	BundlerURL            string
	EntryPoint            string
	EntryPointAddress     string
	SimpleAccountFactory  string
	ERC721Address         string
	EntryPointDeployBlock uint64
	ChainID               uint64
}

func loadChain() ChainConfig {
	entryPoint := mustenv("ENTRY_POINT")
	return ChainConfig{
		RPCURL:                getenv("CHAIN_RPC_URL", ""),
		BundlerURL:            getenv("BUNDLER_URL", ""),
		EntryPoint:            entryPoint,
		EntryPointAddress:     getenv("ENTRYPOINT_ADDRESS", entryPoint),
		SimpleAccountFactory:  getenv("FACTORY_ADDRESS", ""),
		ERC721Address:         getenv("ERC721_ADDRESS", ""),
		EntryPointDeployBlock: u64env("ENTRY_POINT_DEPLOY_BLOCK", 0),
		ChainID:               u64env("CHAIN_ID", 0),
	}
}
