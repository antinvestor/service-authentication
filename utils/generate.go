package utils

import (
	crand "crypto/rand"
	"math/rand"
	"time"
	"unsafe"
)

var src = rand.NewSource(time.Now().UnixNano())

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

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
	if _, err := crand.Read(randomBytes); err != nil {
		return nil, err
	}
	return randomBytes, nil
}

func GenerateRandomStringEfficient(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return *(*string)(unsafe.Pointer(&b))
}
