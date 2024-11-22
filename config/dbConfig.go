package config

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// database connection
var DB *gorm.DB

func LoadDBConfig() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Error loading .env file")
	}

	// DSN: Database Source Name
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_SSLMODE"))

	// tries to connect to database
	var errDb error
	DB, errDb = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if errDb != nil {
		log.Fatal("Failed to connect to database")
	}

	// database migration
	err = DB.AutoMigrate(&News{}, &User{}, &Keyword{})
	if err != nil {
		log.Fatal("Failed to migrate database: ", err)
	}
}

type News struct {
	ID       uint           `gorm:"primaryKey"`
	Title    string         `gorm:"type:varchar(255);not null"`
	Summary  string         `gorm:"type:text"`
	Source   string         `gorm:"type:varchar(255);not null"`
	URL      string         `gorm:"type:varchar(255);not null"`
	Keywords pq.StringArray `gorm:"type:text[]"`
}

type User struct {
	ID       uint      `gorm:"primaryKey"`
	Email    string    `gorm:"unique;not null"`
	Keywords []Keyword `gorm:"many2many:user_keywords;"`
}

type Keyword struct {
	ID    uint   `gorm:"primaryKey"`
	Word  string `gorm:"type:varchar(255);unique;not null"`
	Users []User `gorm:"many2many:user_keywords;"`
}
