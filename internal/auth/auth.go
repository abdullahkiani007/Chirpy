package auth

import "golang.org/x/crypto/bcrypt"

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
