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
	); err != nil {
		log.Fatalf("auto migrate: %v", err)
	}
}
