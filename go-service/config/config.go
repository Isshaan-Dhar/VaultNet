package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	PostgresDSN string
	RedisAddr   string
	JWTSecret   string
	AESKey      []byte
	AppPort     string
}

func Load() *Config {
	_ = godotenv.Load("../.env")
	_ = godotenv.Load(".env")

	aesKey := os.Getenv("AES_KEY")
	if len(aesKey) != 32 {
		log.Fatal("AES_KEY must be exactly 32 characters")
	}

	pgUser := os.Getenv("POSTGRES_USER")
	pgPass := os.Getenv("POSTGRES_PASSWORD")
	pgDB := os.Getenv("POSTGRES_DB")
	pgHost := os.Getenv("POSTGRES_HOST")
	pgPort := os.Getenv("POSTGRES_PORT")

	if pgPort == "" {
		pgPort = "5432"
	}

	redisHost := os.Getenv("REDIS_HOST")
	redisPort := os.Getenv("REDIS_PORT")
	if redisPort == "" {
		redisPort = "6379"
	}

	appPort := os.Getenv("APP_PORT")
	if appPort == "" {
		appPort = "8080"
	}

	return &Config{
		PostgresDSN: "postgres://" + pgUser + ":" + pgPass + "@" + pgHost + ":" + pgPort + "/" + pgDB + "?sslmode=disable",
		RedisAddr:   redisHost + ":" + redisPort,
		JWTSecret:   os.Getenv("JWT_SECRET"),
		AESKey:      []byte(aesKey),
		AppPort:     appPort,
	}
}
