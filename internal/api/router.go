// router.go
package api

import (
	"net/http"
)

func NewRouter(cfg *ApiConfig) http.Handler {
	mux := http.NewServeMux()
	// routes

	mux.HandleFunc("POST /api/users", cfg.createUser)
	mux.Handle("PUT /api/users", cfg.isAuth(http.HandlerFunc(cfg.updateUser)))
	mux.HandleFunc("POST /api/login", cfg.loginUser)
	mux.HandleFunc("POST /admin/reset", cfg.reset)
	mux.Handle("POST /api/chirps", cfg.isAuth(http.HandlerFunc(cfg.createChirp)))
	mux.HandleFunc("GET /api/chirps", cfg.getAllChirps)
	mux.HandleFunc("GET /api/chirps/{id}", cfg.getChirp)
	mux.Handle("DELETE /api/chirps/{id}", cfg.isAuth(http.HandlerFunc(cfg.deleteChirp)))
	mux.HandleFunc("POST /api/refresh", cfg.refresh)
	mux.HandleFunc("POST /api/polka/webhooks", cfg.subscribe)
	mux.HandleFunc("POST /api/revoke", cfg.revoke)
	return mux
}
