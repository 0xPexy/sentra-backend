package store

import (
	"log"
)

// EnsureAdminAddress makes sure the configured admin address
// has a backing Admin row for foreign-key relations.
func EnsureAdminAddress(db *DB, address string) {
	addr := NormalizeAddress(address)
	if addr == "" {
		return
	}
	var count int64
	if err := db.Model(&Admin{}).Where("address = ?", addr).Count(&count).Error; err != nil {
		log.Fatalf("admin lookup failed: %v", err)
	}
	if count > 0 {
		return
	}
	payload := map[string]any{"address": addr}
	if db.Migrator().HasColumn(&Admin{}, "username") {
		payload["username"] = addr
	}
	if err := db.Table("admins").Create(payload).Error; err != nil {
		log.Fatalf("create admin failed: %v", err)
	}
	log.Printf("seeded admin account %s", addr)
}
