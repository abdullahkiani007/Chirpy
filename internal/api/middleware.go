package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/abdullahkiani007/Chirpy/internal/auth"
)

func (cfg *ApiConfig) isAuth(next http.Handler) http.Handler {
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
