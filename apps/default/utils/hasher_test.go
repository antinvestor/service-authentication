package utils

import (
	"context"
	"testing"

	"github.com/stretchr/testify/suite"
)

type HasherTestSuite struct {
	suite.Suite
}

func (s *HasherTestSuite) TestBCrypt_HashAndCompare() {
	bcrypt := NewBCrypt()
	ctx := context.Background()

	hash, err := bcrypt.Hash(ctx, []byte("password123"))
	s.Require().NoError(err)
	s.NotEmpty(hash)

	err = bcrypt.Compare(ctx, hash, []byte("password123"))
	s.NoError(err)
}

func (s *HasherTestSuite) TestBCrypt_CompareWrongPassword() {
	bcrypt := NewBCrypt()
	ctx := context.Background()

	hash, err := bcrypt.Hash(ctx, []byte("correct-password"))
	s.Require().NoError(err)

	err = bcrypt.Compare(ctx, hash, []byte("wrong-password"))
	s.Error(err)
}

func (s *HasherTestSuite) TestBCrypt_DifferentHashesForSameInput() {
	bcrypt := NewBCrypt()
	ctx := context.Background()

	hash1, err := bcrypt.Hash(ctx, []byte("password"))
	s.Require().NoError(err)

	hash2, err := bcrypt.Hash(ctx, []byte("password"))
	s.Require().NoError(err)

	s.NotEqual(hash1, hash2, "bcrypt should produce different hashes due to random salt")
}

func (s *HasherTestSuite) TestHashStringSecret() {
	result := HashStringSecret("my-secret")
	s.Len(result, 64, "SHA256 hex string should be 64 characters")

	// Same input should produce same output
	result2 := HashStringSecret("my-secret")
	s.Equal(result, result2)

	// Different input should produce different output
	result3 := HashStringSecret("different-secret")
	s.NotEqual(result, result3)
}

func (s *HasherTestSuite) TestHashByteSecret() {
	result := HashByteSecret([]byte("my-secret"))
	s.Len(result, 32, "SHA256 should produce 32 bytes")

	// Same input should produce same output
	result2 := HashByteSecret([]byte("my-secret"))
	s.Equal(result, result2)
}

func (s *HasherTestSuite) TestHashByteSecret_EmptyInput() {
	result := HashByteSecret([]byte(""))
	s.Len(result, 32)
}

func TestHasher(t *testing.T) {
	suite.Run(t, new(HasherTestSuite))
}
