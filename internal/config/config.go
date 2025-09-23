package config

import (
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	DBURL     string
	JWTSecret string
	PolkaKey  string
	Addr      string
}

func Load() Config {
	_ = godotenv.Load()
	return Config{
		DBURL:     os.Getenv("DB_URL"),
		JWTSecret: os.Getenv("JWT_SECRET"),
		PolkaKey:  os.Getenv("POLKA_KEY"),
		Addr:      ":8080",
	}
}
