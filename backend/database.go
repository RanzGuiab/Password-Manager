package main

import (
	"fmt"
	"os"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

type User struct {
    ID           uint     `gorm:"primaryKey" json:"id"`
    Username     string   `gorm:"unique;not null" json:"username"`
    PasswordHash string   `gorm:"not null" json:"password_hash"`
    Secrets      []Secret `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

type Secret struct {
    ID                uint   `gorm:"primaryKey;autoIncrement" json:"id"`
    UserID            uint   `gorm:"not null;index" json:"user_id"`
    SiteName          string `gorm:"not null" json:"site_name"`
    SiteUsername      string `gorm:"not null" json:"site_username"`
    EncryptedPassword string `gorm:"not null" json:"encrypted_password"`
    IV                string `gorm:"not null" json:"iv"`
}

func InitDB() {
	user := os.Getenv("POSTGRES_USER")
	pass := os.Getenv("POSTGRES_PASSWORD")
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	dbname := os.Getenv("POSTGRES_DB")

	// URL-style DSN is often more reliable with the pgx driver GORM uses
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		user, pass, host, port, dbname)

	fmt.Printf("🐘 Connecting to DB at %s:%s as user %s...\n", host, port, user)

	var err error
	// Retry loop: Attempt to connect 10 times with a 2-second delay
	for i := 1; i <= 10; i++ {
		fmt.Printf("🔄 Database connection attempt %d/10...\n", i)
		DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})

		if err == nil {
			// Check if the connection is actually alive
			sqlDB, _ := DB.DB()
			if err = sqlDB.Ping(); err == nil {
				fmt.Println("🐘 Database connection established!")

				fmt.Println("Running Auto-Migrations...")
				err = DB.AutoMigrate(&User{}, &Secret{})
				if err != nil {
					fmt.Printf("Migration Failed: %v\n", err)
				}
				return
			}
		}

		fmt.Printf("⏳ DB not ready yet: %v. Retrying in 2s...\n", err)
		time.Sleep(2 * time.Second)
	}

	fmt.Printf("❌ CRITICAL: Could not connect to DB after 10 attempts: %v\n", err)
	os.Exit(1)
}
