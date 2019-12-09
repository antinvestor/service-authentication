package utils

import (
	"context"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"

	"crypto/sha256"
)

const defaultBCryptWorkFactor = 12

// BCrypt implements a BCrypt hasher.
type BCrypt struct {
	bCryptWorkFactor int
}

// NewBCrypt returns a new BCrypt instance.
func NewBCrypt() *BCrypt {
	return &BCrypt{
		defaultBCryptWorkFactor,
	}
}

func (b *BCrypt) Hash(ctx context.Context, data []byte) ([]byte, error) {
	cf := b.bCryptWorkFactor
	s, err := bcrypt.GenerateFromPassword(data, cf)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return s, nil
}

func (b *BCrypt) Compare(ctx context.Context, hash, data []byte) error {
	if err := bcrypt.CompareHashAndPassword(hash, data); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// HashStringSecret hashes the secret for consumption by the AEAD encryption algorithm which expects exactly 32 bytes.
//
// The system secret is being hashed to always match exactly the 32 bytes required by AEAD, even if the secret is long or
// shorter.
func HashStringSecret(secret string) []byte {
	return HashByteSecret([]byte(secret))
}

// HashByteSecret hashes the secret for consumption by the AEAD encryption algorithm which expects exactly 32 bytes.
//
// The system secret is being hashed to always match exactly the 32 bytes required by AEAD, even if the secret is long or
// shorter.
func HashByteSecret(secret []byte) []byte {
	var r [32]byte
	r = sha256.Sum256([]byte(secret))
	return r[:]
}
