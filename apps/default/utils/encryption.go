package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

func AesEncrypt(key []byte, plaintext string) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, 12)

	if _, errRand := io.ReadFull(rand.Reader, nonce); errRand != nil {
		return nil, nonce, errRand
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nonce, err
	}

	return aesgcm.Seal(nil, nonce, []byte(plaintext), nil), nonce, nil

}

func AesDecrypt(key []byte, nonce []byte, ciphertext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	return string(plaintext), err
}
