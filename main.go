package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/abdullahkiani007/Chirpy/internal/auth"
	"github.com/abdullahkiani007/Chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	jwtSecret      string
	polkakey       string
}

type chirpStruct struct {
	Id        string `json:"id"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	UserId    string `json:"user_id"`
	Body      string `json:"body"`
}

func (cfg *apiConfig) getHits(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	val := cfg.fileserverHits.Load()

	fmt.Printf("my boy metrics %v", val)
	fmt.Fprintf(w, `<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, val)
}
func (cfg *apiConfig) isAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized"))
			return
		}
		uId, err := auth.ValidateJWT(token, cfg.jwtSecret)
		if err != nil {
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized"))
			return
		}

		buf, _ := io.ReadAll(r.Body)
		var bodyMap map[string]interface{}
		if len(buf) > 0 {
			// Unmarshal the body if it's not empty
			err = json.Unmarshal(buf, &bodyMap)
			if err != nil {
				http.Error(w, "Failed to unmarshal JSON", http.StatusBadRequest)
				return
			}
		} else {
			bodyMap = make(map[string]interface{}) // Initialize if body was empty
		}

		bodyMap["user_id"] = uId.String()
		modifiedBody, _ := json.Marshal(bodyMap)
		r.Body = io.NopCloser(bytes.NewBuffer(modifiedBody))
		r.ContentLength = int64(len(modifiedBody))

		next.ServeHTTP(w, r)

	})
}

func (cfg *apiConfig) createUser(w http.ResponseWriter, r *http.Request) {
	type req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	type errorStruct struct {
		Error string
	}

	type userStruct struct {
		Id          string `json:"id"`
		CreatedAt   string `json:"created_at"`
		UpdatedAt   string `json:"updated_at"`
		Email       string `json:"email"`
		IsChirpyRed bool   `json:"is_chirpy_red"`
	}

	decoder := json.NewDecoder(r.Body)
	reqStruct := req{}
	err := decoder.Decode(&reqStruct)
	w.Header().Set("Content-Type", "application/json")

	if len(reqStruct.Email) == 0 || len(reqStruct.Password) == 0 {
		w.WriteHeader(400)
		w.Write([]byte("Password and Email are required"))
		return
	}
	if err != nil {
		fmt.Printf("error decoding req %v", err)
		w.WriteHeader(500)
		err := errorStruct{
			Error: "Something went wrong",
		}
		data, _ := json.Marshal(err)
		w.Write(data)
		return
	}
	fmt.Printf("password %v", reqStruct.Password)

	hashedPassword, err := auth.HashPassword(reqStruct.Password)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte("Error hashing password"))
		return
	}

	// map user fields to parameters required by db
	userParams := database.CreateUserParams{
		Email:          reqStruct.Email,
		HashedPassword: hashedPassword,
	}
	user, err := cfg.db.CreateUser(r.Context(), userParams)

	if err != nil {
		fmt.Printf("error creating user %v", err)
		w.WriteHeader(400)
		w.Write([]byte("Something went wrong"))
		return
	}

	newUser := userStruct{
		Id:          user.ID.String(),
		CreatedAt:   user.CreatedAt.String(),
		UpdatedAt:   user.UpdatedAt.String(),
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	}
	u, _ := json.Marshal(newUser)

	w.WriteHeader(201)
	w.Write(u)

}

func (cfg *apiConfig) updateUser(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		UserId   string `json:"user_id"`
	}

	type response struct {
		Id          string `json:"id"`
		Email       string `json:"email"`
		Created_at  string `json:"created_at"`
		Updated_at  string `json:"updated_at"`
		IsChirpyRed bool   `json:"is_chirpy_red"`
	}

	user := request{}
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&user)

	hashpPass, _ := auth.HashPassword(user.Password)
	if len(user.Email) == 0 || len(user.Password) == 0 {
		w.WriteHeader(400)
		w.Write([]byte("Password and Email are required"))
		return
	}
	updateUserparam := database.UpdateUserParams{
		Email:          user.Email,
		HashedPassword: hashpPass,
		ID:             uuid.MustParse(user.UserId),
	}

	newUser, err := cfg.db.UpdateUser(r.Context(), updateUserparam)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte("Error while updating email and password"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	userRes := response{
		Id:          newUser.ID.String(),
		Email:       newUser.Email,
		Updated_at:  newUser.UpdatedAt.String(),
		Created_at:  newUser.CreatedAt.String(),
		IsChirpyRed: newUser.IsChirpyRed,
	}

	uData, _ := json.Marshal(userRes)
	w.Write(uData)

}
func (cfg *apiConfig) loginUser(w http.ResponseWriter, r *http.Request) {
	type loginReq struct {
		Email            string `json:"email"`
		Password         string `json:"password"`
		ExpiresInSeconds int    `json:"expires_in_seconds"`
	}
	type userResStruct struct {
		Id           string `json:"id"`
		CreatedAt    string `json:"created_at"`
		UpdatedAt    string `json:"updated_at"`
		Email        string `json:"email"`
		Token        string `json:"token"`
		IsChirpyRed  bool   `json:"is_chirpy_red"`
		RefreshToken string `json:"refresh_token"`
	}
	type errorStruct struct {
		Error string
	}

	decoder := json.NewDecoder(r.Body)
	userStruct := loginReq{}
	err := decoder.Decode(&userStruct)
	w.Header().Set("Content-Type", "application/json")

	if len(userStruct.Email) == 0 || len(userStruct.Password) == 0 {
		w.WriteHeader(400)
		w.Write([]byte("Password and Email are required"))
		return
	}

	if err != nil {
		fmt.Printf("error decoding req %v", err)
		w.WriteHeader(500)
		err := errorStruct{
			Error: "Something went wrong",
		}
		data, _ := json.Marshal(err)
		w.Write(data)
		return
	}

	user, err := cfg.db.GetUser(r.Context(), userStruct.Email)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Request failed to fetch user"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	isError := auth.CheckPasswordHash(userStruct.Password, user.HashedPassword)
	if isError != nil {
		w.WriteHeader(401)
		w.Write([]byte("Incorrect Password"))
		return
	}

	// by default 1 hour
	expires_in_second := 3600
	expires_in_days := 1440 // 60 days

	seconds := fmt.Sprintf("%ds", expires_in_second)
	days := fmt.Sprintf("%dh", expires_in_days)

	duration, _ := time.ParseDuration(seconds)
	daysDuration, _ := time.ParseDuration(days)
	revokeDuration := time.Time.Add(time.Now().UTC(), daysDuration)

	jwt, err := auth.MakeJWT(user.ID, cfg.jwtSecret, duration)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte("Error creating jwt"))
		return
	}

	refresh, _ := auth.MakeRefreshToken()

	refreshToken := database.CreateTokenParams{
		Token:     refresh,
		UserID:    user.ID,
		ExpiresAt: revokeDuration,
	}

	token, err := cfg.db.CreateToken(r.Context(), refreshToken)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte("Error storing refresh token"))
		return
	}

	userRes := userResStruct{
		Id:           user.ID.String(),
		CreatedAt:    user.CreatedAt.String(),
		UpdatedAt:    user.UpdatedAt.String(),
		Email:        user.Email,
		Token:        jwt,
		RefreshToken: token.Token,
		IsChirpyRed:  user.IsChirpyRed,
	}

	u, _ := json.Marshal(userRes)
	w.WriteHeader(200)
	w.Write([]byte(u))

}

func (cfg *apiConfig) reset(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits.Store(0)
	w.WriteHeader(http.StatusOK)
}

func (cfg *apiConfig) subscribe(w http.ResponseWriter, r *http.Request) {
	type reqStruct struct {
		Event string `json:"event"`
		Data  struct {
			UserId string `json:"user_id"`
		} `json:"data"`
	}

	key, err := auth.GetApikey(r.Header)
	if err != nil || key != cfg.polkakey {
		w.WriteHeader(401)
		return
	}

	decoder := json.NewDecoder(r.Body)
	event := reqStruct{}

	decoder.Decode(&event)
	if event.Event != "user.upgraded" {
		w.WriteHeader(204)
		return
	}

	fmt.Printf("event %v", event)
	userUid, err := uuid.Parse(event.Data.UserId)
	if err != nil {
		fmt.Printf("error parsing uuid %v", err)
		w.WriteHeader(204)
		return
	}

	user, err := cfg.db.SubscribeUser(r.Context(), userUid)
	if err != nil {
		w.WriteHeader(404)
		fmt.Printf("there's an error %v", err)
		return
	}
	fmt.Printf("user updated %v", user)

	w.WriteHeader(204)
}

// implement auth middleware

func (cfg *apiConfig) midMetInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func fServer(folder string) http.Handler {
	return http.FileServer(http.Dir(folder))
}

func (cfg *apiConfig) createChirp(w http.ResponseWriter, r *http.Request) {
	FilteredWords := []string{"kerfuffle", "sharbert", "fornax"}

	type validStructure struct {
		Body   string `json:"body"`
		UserId string `json:"user_id"`
	}

	type errorStructure struct {
		Error string `json:"error"`
	}

	decoder := json.NewDecoder(r.Body)
	structure := validStructure{}
	err := decoder.Decode(&structure)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		error := errorStructure{
			Error: "Something went wrong",
		}
		data, err := json.Marshal(error)
		if err != nil {
			log.Printf("Error marshalling json %v", err)
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write(data)
		return
	}
	if len(structure.Body) <= 140 {
		cleanStr := ""
		for word := range strings.SplitSeq(structure.Body, " ") {
			if slices.Contains(FilteredWords, strings.ToLower(string(word))) {
				cleanStr += "****"
				cleanStr += " "
				continue
			}
			cleanStr += string(word) + " "
		}
		cleanStr = strings.Trim(cleanStr, " ")
		newUuid, _ := uuid.Parse(structure.UserId)
		params := database.CreateChirpParams{
			Body:   structure.Body,
			UserID: newUuid,
		}
		msg, err := cfg.db.CreateChirp(r.Context(), params)
		if err != nil {
			w.WriteHeader(400)
			fmt.Printf("Error creating chirp %v", err)
			w.Write([]byte("Some thing went wrong"))
		}
		resChirp := chirpStruct{
			Id:        msg.ID.String(),
			CreatedAt: msg.CreatedAt.String(),
			UpdatedAt: msg.UpdatedAt.String(),
			UserId:    msg.UserID.String(),
			Body:      msg.Body,
		}
		res, _ := json.Marshal(resChirp)
		w.WriteHeader(http.StatusCreated)
		w.Write(res)
		return
	}
	invalid := errorStructure{
		Error: "Chirp is too long",
	}
	data, _ := json.Marshal(invalid)
	w.WriteHeader(400)
	w.Write(data)

}

func (cfg *apiConfig) getAllChirps(w http.ResponseWriter, r *http.Request) {
	data, err := cfg.db.GetAllChirps(r.Context())
	if err != nil {
		w.WriteHeader(400)
		fmt.Printf("Error getting chirps %v \n", err)
		w.Write([]byte("Something went wrong"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	newChirp := []chirpStruct{}
	for _, c := range data {
		chirp := chirpStruct{
			Id:        c.ID.String(),
			CreatedAt: c.CreatedAt.String(),
			UpdatedAt: c.UpdatedAt.String(),
			UserId:    c.UserID.String(),
			Body:      c.Body,
		}
		newChirp = append(newChirp, chirp)
	}
	res, _ := json.Marshal(newChirp)
	w.Write(res)
}

func (cfg *apiConfig) getChirp(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	fmt.Printf("fetchng chirp by ID %v\n", id)
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid id"))
		return
	}
	newId, err := uuid.Parse(id)
	if err != nil {
		fmt.Printf("error converting id to uuid error: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error while converting id to uuid"))
		return
	}
	fmt.Printf("converting id to uuid %v\n", newId)
	data, err := cfg.db.GetChirp(r.Context(), newId)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Printf("Some thing went wrong while fetching chirp %v \n", err)
		w.Write([]byte("Some thing went wrong while fetching chirp"))
		return
	}

	newData := chirpStruct{
		Id:        data.ID.String(),
		CreatedAt: data.CreatedAt.String(),
		UpdatedAt: data.UpdatedAt.String(),
		UserId:    data.UserID.String(),
		Body:      data.Body,
	}

	res, _ := json.Marshal(newData)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(res)

}
func (cfg *apiConfig) deleteChirp(w http.ResponseWriter, r *http.Request) {
	type reqStruct struct {
		UserId string `json:"user_id"`
	}

	decode := json.NewDecoder(r.Body)
	userReq := reqStruct{}

	decode.Decode(&userReq)

	id := r.PathValue("id")
	userUid, uError := uuid.Parse(userReq.UserId)
	chirpUid, cError := uuid.Parse(id)

	if uError != nil || cError != nil {
		w.WriteHeader(403)
		w.Write([]byte("invalid chirp id or user id"))
		return
	}

	chirp, err := cfg.db.GetChirp(r.Context(), chirpUid)
	if err != nil {
		w.WriteHeader(404)
		w.Write([]byte("chirp not found"))
		return
	}

	if chirp.UserID != userUid {
		w.WriteHeader(403)
		w.Write([]byte("Bad request"))
		return
	}

	cfg.db.DeleteChirp(r.Context(), chirpUid)
	w.WriteHeader(204)
	w.Write([]byte("chirp is deleted successfully"))

}

func (cfg *apiConfig) refresh(w http.ResponseWriter, r *http.Request) {
	type resStruct struct {
		Token string `json:"token"`
	}

	w.Header().Set("Content-Type", "application/json")
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Error validating token %v", err)
		return
	}

	user, err := cfg.db.GetUserFromRefreshToken(r.Context(), token)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Error validating token %v", err)
		return
	}
	// by default 1 hour
	expires_in_second := 3600
	seconds := fmt.Sprintf("%ds", expires_in_second)
	duration, _ := time.ParseDuration(seconds)

	newToken, err := auth.MakeJWT(user, cfg.jwtSecret, duration)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Error creating token %v", err)
		return
	}

	response := resStruct{
		Token: newToken,
	}

	processed_res, _ := json.Marshal(response)
	w.WriteHeader(200)
	w.Write(processed_res)

}

func (cfg *apiConfig) revoke(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Error validating token %v", err)
		return
	}
	cfg.db.RevokeToken(r.Context(), token)
	w.WriteHeader(204)
}
func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Panicf("failed to connect to db %s", err)
	}

	dbQueries := database.New(db)
	mux := http.NewServeMux()
	cfg := apiConfig{
		db:        dbQueries,
		jwtSecret: os.Getenv("JWT_SECRET"),
		polkakey:  os.Getenv("POLKA_KEY"),
	}

	checkHealth := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8") // normal header
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}

	// routes
	mux.Handle("/app/",
		cfg.midMetInc(
			http.StripPrefix("/app/", fServer("."))))

	mux.HandleFunc("POST /api/users", cfg.createUser)
	mux.Handle("PUT /api/users", cfg.isAuth(http.HandlerFunc(cfg.updateUser)))
	mux.HandleFunc("POST /api/login", cfg.loginUser)
	mux.HandleFunc("GET /api/healthz", checkHealth)
	mux.HandleFunc("GET /admin/metrics", cfg.getHits)
	mux.HandleFunc("POST /admin/reset", cfg.reset)
	mux.Handle("POST /api/chirps", cfg.isAuth(http.HandlerFunc(cfg.createChirp)))
	mux.HandleFunc("GET /api/chirps", cfg.getAllChirps)
	mux.HandleFunc("GET /api/chirps/{id}", cfg.getChirp)
	mux.Handle("DELETE /api/chirps/{id}", cfg.isAuth(http.HandlerFunc(cfg.deleteChirp)))
	mux.HandleFunc("POST /api/refresh", cfg.refresh)
	mux.HandleFunc("POST /api/polka/webhooks", cfg.subscribe)
	mux.HandleFunc("POST /api/revoke", cfg.revoke)

	server := &http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	server.ListenAndServe()
}
