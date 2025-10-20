package store

import (
	"log"

	"golang.org/x/crypto/bcrypt"
)

func EnsureAdmin(db *DB, username, password string) {
	if username == "" || password == "" {
		return
	}
	var count int64
	if err := db.Model(&Admin{}).Where("username = ?", username).Count(&count).Error; err != nil {
		log.Fatalf("admin lookup failed: %v", err)
	}
	if count > 0 {
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("admin hash failed: %v", err)
	}
	admin := Admin{
		Username: username,
		PassHash: string(hash),
	}
	if err := db.Create(&admin).Error; err != nil {
		log.Fatalf("create admin failed: %v", err)
	}
	log.Printf("seeded admin account %s", username)
}

func EnsureDevAdmin(db *DB, id uint, username string) {
	if id == 0 || username == "" {
		return
	}
	var existing Admin
	if err := db.First(&existing, id).Error; err == nil {
		return
	}
	if err := db.First(&existing, "username = ?", username).Error; err == nil {
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("dev-token"), bcrypt.MinCost)
	if err != nil {
		log.Printf("dev admin hash failed: %v", err)
		return
	}
	admin := Admin{
		ID:       id,
		Username: username,
		PassHash: string(hash),
	}
	if err := db.Create(&admin).Error; err != nil {
		log.Printf("create dev admin failed: %v", err)
		return
	}
	log.Printf("seeded dev admin %s (id=%d)", username, id)
}
