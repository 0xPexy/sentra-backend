package config

type PaymasterConfig struct {
	PolicyPrivateKey string
	ValidationGas    uint64
	PostOpGas        uint64
	DefaultUSDPer    int64
}

func loadPaymaster() PaymasterConfig {
	return PaymasterConfig{
		PolicyPrivateKey: mustenv("POLICY_SIGNER_PK"),
		ValidationGas:    u64env("PM_VALIDATION_GAS", 120_000),
		PostOpGas:        u64env("PM_POSTOP_GAS", 80_000),
		DefaultUSDPer:    i64env("USD_PER_MAX_OP_DEFAULT", 1),
	}
}
