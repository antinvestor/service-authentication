package utils

import "crypto/rand"

func GenerateRandomString(length int) (string, error) {
	randomBytes, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}

	return string(randomBytes), nil
}

// GenerateRandomBytes returns the requested number of bytes using crypto/rand
func GenerateRandomBytes(length int) ([]byte, error) {
	var randomBytes = make([]byte, length)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, err
	}
	return randomBytes, nil
}
