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
	ID     uint `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID uint `gorm:"not null;index" json:"user_id"`

	EncryptedSiteName     string `gorm:"type:text" json:"encrypted_site_name"`
	SiteNameIV            string `gorm:"type:text" json:"site_name_iv"`
	EncryptedSiteUsername string `gorm:"type:text" json:"encrypted_site_username"`
	SiteUsernameIV        string `gorm:"type:text" json:"site_username_iv"`

	EncryptedPassword string `gorm:"type:text;not null" json:"encrypted_password"`
	IV                string `gorm:"type:text;not null" json:"iv"`
	EncVersion        string `gorm:"type:varchar(16);default:v1" json:"enc_version"`
}

func enforceStrictSecretSchema(db *gorm.DB) error {
	var missing int64
	if err := db.Table("secrets").
		Where(`
			encrypted_site_name IS NULL OR
			site_name_iv IS NULL OR
			encrypted_site_username IS NULL OR
			site_username_iv IS NULL OR
			encrypted_password IS NULL OR
			iv IS NULL
		`).
		Count(&missing).Error; err != nil {
		return err
	}
	if missing > 0 {
		return fmt.Errorf("found %d legacy/plaintext secret rows; migrate/delete them before strict schema", missing)
	}

	if err := db.Exec(`UPDATE secrets SET enc_version='v1' WHERE enc_version IS NULL OR enc_version=''`).Error; err != nil {
		return err
	}

	stmts := []string{
		`ALTER TABLE secrets ALTER COLUMN encrypted_site_name SET NOT NULL`,
		`ALTER TABLE secrets ALTER COLUMN site_name_iv SET NOT NULL`,
		`ALTER TABLE secrets ALTER COLUMN encrypted_site_username SET NOT NULL`,
		`ALTER TABLE secrets ALTER COLUMN site_username_iv SET NOT NULL`,
		`ALTER TABLE secrets ALTER COLUMN encrypted_password SET NOT NULL`,
		`ALTER TABLE secrets ALTER COLUMN iv SET NOT NULL`,
		`ALTER TABLE secrets ALTER COLUMN enc_version SET NOT NULL`,
		`ALTER TABLE secrets ALTER COLUMN enc_version SET DEFAULT 'v1'`,
		`ALTER TABLE secrets DROP COLUMN IF EXISTS site_name`,
		`ALTER TABLE secrets DROP COLUMN IF EXISTS site_username`,
	}
	for _, stmt := range stmts {
		if err := db.Exec(stmt).Error; err != nil {
			return err
		}
	}
	return nil
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
					os.Exit(1)
				}

				if err := enforceStrictSecretSchema(DB); err != nil {
					fmt.Printf("Migration Failed: %v\n", err)
					os.Exit(1)
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
