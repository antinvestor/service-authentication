// Copyright 2023-2026 Ant Investor Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/bcrypt"
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
		return nil, err
	}
	return s, nil
}

func (b *BCrypt) Compare(ctx context.Context, hash, data []byte) error {
	if err := bcrypt.CompareHashAndPassword(hash, data); err != nil {
		return err
	}
	return nil
}

// HashStringSecret hashes the secret for consumption by the AEAD encryption algorithm which expects exactly 32 bytes.
//
// The system secret is being hashed to always match exactly the 32 bytes required by AEAD, even if the secret is long or
// shorter.
func HashStringSecret(secret string) string {
	hashedSecret := HashByteSecret([]byte(secret))
	return hex.EncodeToString(hashedSecret)
}

// HashByteSecret hashes the secret for consumption by the AEAD encryption algorithm which expects exactly 32 bytes.
//
// The system secret is being hashed to always match exactly the 32 bytes required by AEAD, even if the secret is long or
// shorter.
func HashByteSecret(secret []byte) []byte {

	algorithm := sha256.New()
	algorithm.Write(secret)
	return algorithm.Sum(nil)
}
