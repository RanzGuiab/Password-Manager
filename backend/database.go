package main

import (
	"fmt"
	"os"
	"time"

	"github.com/rnz.gwb/Password-Manager/backend/api"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

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
				return
			}
		}

		fmt.Printf("⏳ DB not ready yet: %v. Retrying in 2s...\n", err)
		time.Sleep(2 * time.Second)

		fmt.Println("Running Auto-Migrations...")
		DB.AutoMigrate(&api.UserAuth{}, &api.Secret{})
	}

	fmt.Printf("❌ CRITICAL: Could not connect to DB after 10 attempts: %v\n", err)
	os.Exit(1)
}
