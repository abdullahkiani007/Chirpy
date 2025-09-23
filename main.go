package main

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/abdullahkiani007/Chirpy/internal/api"
	"github.com/abdullahkiani007/Chirpy/internal/config"
	"github.com/abdullahkiani007/Chirpy/internal/database"
	_ "github.com/lib/pq"
)

func main() {
	cfgFile := config.Load()

	db, err := sql.Open("postgres", cfgFile.DBURL)
	if err != nil {
		log.Panicf("failed to connect to db: %s", err)
	}

	dbQueries := database.New(db)

	cfg := api.NewApiConfig(dbQueries, cfgFile.JWTSecret, cfgFile.PolkaKey)
	router := api.NewRouter(cfg)

	server := &http.Server{
		Handler: router,
		Addr:    cfgFile.Addr,
	}

	log.Printf("Server listening on %s", cfgFile.Addr)
	log.Fatal(server.ListenAndServe())
}
