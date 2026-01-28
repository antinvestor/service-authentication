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

// Expirable is an interface for state types that have an expiration time.
// When decoding, if the state implements this interface and is expired,
// an error will be returned.
type Expirable interface {
	IsExpired() bool
}

type AuthState struct {
	Provider     string    `json:"provider"`
	State        string    `json:"state"`
	PKCEVerifier string    `json:"pkce_verifier"`
	LoginEventID string    `json:"login_event_id"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// IsExpired implements Expirable for AuthState.
func (a *AuthState) IsExpired() bool {
	return time.Now().After(a.ExpiresAt)
}

// StateCodec provides authenticated encryption for cookie values.
// It uses AES-GCM to encrypt and authenticate data, with a name included
// in the authenticated data to prevent cookie swapping attacks.
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

// Encode encrypts and encodes a value with an associated name.
// The name is included in the authenticated data to prevent cookie swapping.
// The value can be any JSON-serializable type.
func (c *StateCodec) Encode(name string, value any) (string, error) {
	plaintext, err := json.Marshal(value)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	// Include the name in authenticated data to prevent cookie swapping
	ciphertext := c.aead.Seal(nonce, nonce, plaintext, []byte(name))
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// Decode decrypts and decodes a value with the associated name.
// The dst parameter must be a pointer to the type to decode into.
// If the decoded value implements Expirable and is expired, an error is returned.
func (c *StateCodec) Decode(name string, value string, dst any) error {
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return err
	}

	nonceSize := c.aead.NonceSize()
	if len(data) < nonceSize {
		return errors.New("invalid state: data too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, []byte(name))
	if err != nil {
		return err
	}

	err = json.Unmarshal(plaintext, dst)
	if err != nil {
		return err
	}

	// Check expiration if the type implements Expirable
	if expirable, ok := dst.(Expirable); ok {
		if expirable.IsExpired() {
			return errors.New("state expired")
		}
	}

	return nil
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
