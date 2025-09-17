package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(password), 2)
	if err != nil {
		return "", err
	}

	return string(hashPassword), nil
}

func CheckPasswordHash(password, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	fmt.Printf("duration for expiration is %v will expire at %v", expiresIn, time.Time.Add(time.Now().UTC(), expiresIn))
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Time.Add(time.Now().UTC(), expiresIn)),
		Subject:   userID.String(),
	})

	signedToken, err := token.SignedString([]byte(tokenSecret))
	return signedToken, err

}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	var err error
	type MyCustomClaims struct {
		jwt.RegisteredClaims
	}
	token, err := jwt.ParseWithClaims(tokenString, &MyCustomClaims{}, func(token *jwt.Token) (any, error) {
		return []byte(tokenSecret), nil
	})
	if err != nil {
		return uuid.UUID{}, err
	}
	if !token.Valid {
		return uuid.UUID{}, errors.New("invalid or expired token")
	}
	claims, ok := token.Claims.(*MyCustomClaims)
	if !ok {
		return uuid.UUID{}, errors.New("filaed to parse claims")
	}

	id, _ := claims.GetSubject()
	newId, err := uuid.Parse(id)

	if err != nil {
		return uuid.UUID{}, err
	}

	return newId, nil

}

func GetBearerToken(headers http.Header) (string, error) {
	rawToken := headers.Get("Authorization")
	arr := strings.Split(rawToken, " ")
	if len(arr) != 2 {
		return "", errors.New("invalid token")
	}
	if len(arr[1]) == 0 {
		return "", errors.New("invalid token")
	}

	token := arr[1]

	return token, nil
}

func MakeRefreshToken() (string, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	token := hex.EncodeToString(key)

	if err != nil {
		return "", fmt.Errorf("error creating token %v", err)
	}

	return token, nil
}

func GetApikey(header http.Header) (string, error) {
	auth := header.Get("Authorization")
	payload := strings.Split(auth, " ")
	if len(payload) != 2 {
		return "", errors.New("invalid key")
	}
	if len(payload[1]) == 0 {
		return "", errors.New("invalid key")
	}

	token := payload[1]

	return token, nil

}
