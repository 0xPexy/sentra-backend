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
		&UserOperationTrace{},
		&UserOperationRevert{},
		&AccountDeployment{},
		&SimpleAccountInitialization{},
		&Sponsorship{},
		&IndexerMetric{},
		&NFTToken{},
	); err != nil {
		log.Fatalf("auto migrate: %v", err)
	}
	migrateAdminSchema(db)
}

func migrateAdminSchema(db *DB) {
	migrator := db.Migrator()
	if migrator.HasColumn(&Admin{}, "username") && !migrator.HasColumn(&Admin{}, "address") {
		if err := migrator.RenameColumn(&Admin{}, "username", "address"); err != nil {
			log.Printf("warning: failed to rename admin.username to address: %v", err)
		}
	}
	if migrator.HasColumn(&Admin{}, "pass_hash") {
		if err := migrator.DropColumn(&Admin{}, "pass_hash"); err != nil {
			log.Printf("warning: failed to drop admin.pass_hash: %v", err)
		}
	}
}
