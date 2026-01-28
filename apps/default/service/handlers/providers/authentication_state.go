package providers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

const AuthStateCookie = "__Host-auth_state"

type AuthState struct {
	Provider     string    `json:"provider"`
	State        string    `json:"state"`
	PKCEVerifier string    `json:"pkce_verifier"`
	LoginEventID string    `json:"login_event_id"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type StateCodec struct {
	aead cipher.AEAD
}

func NewStateCodec(key []byte) (*StateCodec, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &StateCodec{aead: aead}, nil
}

func (c *StateCodec) Encode(state *AuthState) (string, error) {
	plaintext, err := json.Marshal(state)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := c.aead.Seal(nonce, nonce, plaintext, nil)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func (c *StateCodec) Decode(value string) (*AuthState, error) {
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}

	nonceSize := c.aead.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("invalid state")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	var state AuthState
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return nil, err
	}

	if time.Now().After(state.ExpiresAt) {
		return nil, errors.New("auth state expired")
	}

	return &state, nil
}

func SetAuthStateCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     AuthStateCookie,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300, // 5 minutes
	})
}

func ClearAuthStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   AuthStateCookie,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}
