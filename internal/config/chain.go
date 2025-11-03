package config

type ChainConfig struct {
	RPCURL                string
	EntryPoint            string
	EntryPointAddress     string
	SimpleAccountFactory  string
	EntryPointDeployBlock uint64
	ChainID               uint64
}

func loadChain() ChainConfig {
	entryPoint := mustenv("ENTRY_POINT")
	return ChainConfig{
		RPCURL:                getenv("CHAIN_RPC_URL", ""),
		EntryPoint:            entryPoint,
		EntryPointAddress:     getenv("ENTRYPOINT_ADDRESS", entryPoint),
		SimpleAccountFactory:  getenv("FACTORY_ADDRESS", ""),
		EntryPointDeployBlock: u64env("ENTRY_POINT_DEPLOY_BLOCK", 0),
		ChainID:               u64env("CHAIN_ID", 0),
	}
}
