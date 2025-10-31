package store

import "log"

func AutoMigrate(db *DB) {
	if err := db.AutoMigrate(
		&Admin{},
		&Paymaster{},
		&ContractWhitelist{},
		&FunctionWhitelist{},
		&UserWhitelist{},
		&Operation{},
		&LogCursor{},
		&UserOperationEvent{},
		&UserOperationRevert{},
		&AccountDeployment{},
		&SimpleAccountInitialization{},
		&Sponsorship{},
		&IndexerMetric{},
	); err != nil {
		log.Fatalf("auto migrate: %v", err)
	}
}
