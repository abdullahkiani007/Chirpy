package auth

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCheckPasswordHash(t *testing.T) {
	// First, we need to create some hashed passwords for testing
	password1 := "correctPassword123!"
	password2 := "anotherPassword456!"
	hash1, _ := HashPassword(password1)
	hash2, _ := HashPassword(password2)

	tests := []struct {
		name     string
		password string
		hash     string
		wantErr  bool
	}{
		{
			name:     "Correct password",
			password: password1,
			hash:     hash1,
			wantErr:  false,
		},
		{
			name:     "Incorrect password",
			password: "wrongPassword",
			hash:     hash1,
			wantErr:  true,
		},
		{
			name:     "Password doesn't match different hash",
			password: password1,
			hash:     hash2,
			wantErr:  true,
		},
		{
			name:     "Empty password",
			password: "",
			hash:     hash1,
			wantErr:  true,
		},
		{
			name:     "Invalid hash",
			password: password1,
			hash:     "invalidhash",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckPasswordHash(tt.password, tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckPasswordHash() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCheckJwt(t *testing.T) {
	userId, _ := uuid.Parse("55b5e63b-d719-415f-9624-0bab13a9ff89")
	duration := time.Hour
	jwt1, _ := MakeJWT(userId, "helloworld", duration)
	jwt2, _ := MakeJWT(userId, "helloworld", -time.Minute)
	jwt3, _ := MakeJWT(userId, "helloworld", duration)

	tests := []struct {
		name           string
		tokenSecret    string
		validateSecret string
		token          string
		wantErr        bool
	}{
		{
			name:           "Valid signature",
			tokenSecret:    "helloworld",
			token:          jwt1,
			validateSecret: "helloworld",
			wantErr:        false,
		},
		{
			name:           "Invalid signature",
			tokenSecret:    "helloworld",
			token:          jwt3,
			validateSecret: "invalidsignature",
			wantErr:        true,
		},
		{
			name:           "Expired token",
			tokenSecret:    "helloworld",
			token:          jwt2,
			validateSecret: "helloworld",
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			_, err := ValidateJWT(tt.token, tt.validateSecret)
			// err = nil
			// false
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateJWT() error = %v, validID %v", err, userId)
			}
		})
	}

}

func TestGetBearerTOken(t *testing.T) {
	req1, _ := http.NewRequest(http.MethodGet, "www.example.com", nil)
	req1.Header.Set("Authorization", "Bearer alskjdflsakdjflkasjdflkjasdflkjasdf")

	req2, _ := http.NewRequest(http.MethodGet, "www.example.com", nil)
	req2.Header.Set("Authorization", "alskjdflsakdjflkasjdflkjasdflkjasdf")

	req3, _ := http.NewRequest(http.MethodGet, "www.example.com", nil)

	req4, _ := http.NewRequest(http.MethodGet, "www.example.com", nil)
	req4.Header.Set("Authorization", "")

	tests := []struct {
		name    string
		req     *http.Request
		wantErr bool
	}{

		{
			name:    "Valid bearer token",
			req:     req1,
			wantErr: false,
		},
		{
			name:    "Invalid token Bearer missing",
			req:     req2,
			wantErr: true,
		},
		{
			name:    "Auth header missing",
			req:     req3,
			wantErr: true,
		},
		{
			name:    "Invalid token missing",
			req:     req4,
			wantErr: true,
		},
	}

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {
			token, err := GetBearerToken(tt.req.Header)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetBearerTOken() err= %v token= %v", err, token)
			}
			if (err == nil) && token != "alskjdflsakdjflkasjdflkjasdflkjasdf" {
				t.Errorf("GetBearerTOken() err= tokens mismatch token= %v", token)
			}

		})
	}

}

func TestRefreshTokenGen(t *testing.T) {
	token1, err := MakeRefreshToken()

	t.Run("testing refresh token generation", func(t *testing.T) {
		if err != nil {
			t.Errorf("MakeRefreshToken() err = %v", err)
		}
		fmt.Printf("token %v", token1)
	})
}
