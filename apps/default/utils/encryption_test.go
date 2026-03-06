package utils

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type EncryptionTestSuite struct {
	suite.Suite
}

func (s *EncryptionTestSuite) TestAesEncryptDecrypt_RoundTrip() {
	key := HashByteSecret([]byte("test-secret-key"))
	plaintext := "hello world"

	ciphertext, nonce, err := AesEncrypt(key, plaintext)
	s.Require().NoError(err)
	s.NotEmpty(ciphertext)
	s.Len(nonce, 12)

	decrypted, err := AesDecrypt(key, nonce, ciphertext)
	s.Require().NoError(err)
	s.Equal(plaintext, decrypted)
}

func (s *EncryptionTestSuite) TestAesEncryptDecrypt_EmptyString() {
	key := HashByteSecret([]byte("key"))

	ciphertext, nonce, err := AesEncrypt(key, "")
	s.Require().NoError(err)

	decrypted, err := AesDecrypt(key, nonce, ciphertext)
	s.Require().NoError(err)
	s.Equal("", decrypted)
}

func (s *EncryptionTestSuite) TestAesEncryptDecrypt_LongText() {
	key := HashByteSecret([]byte("key"))
	plaintext := "This is a much longer text that tests encryption of larger payloads with various characters: !@#$%^&*()"

	ciphertext, nonce, err := AesEncrypt(key, plaintext)
	s.Require().NoError(err)

	decrypted, err := AesDecrypt(key, nonce, ciphertext)
	s.Require().NoError(err)
	s.Equal(plaintext, decrypted)
}

func (s *EncryptionTestSuite) TestAesDecrypt_WrongKey() {
	key1 := HashByteSecret([]byte("key1"))
	key2 := HashByteSecret([]byte("key2"))

	ciphertext, nonce, err := AesEncrypt(key1, "secret data")
	s.Require().NoError(err)

	_, err = AesDecrypt(key2, nonce, ciphertext)
	s.Error(err)
}

func (s *EncryptionTestSuite) TestAesDecrypt_CorruptedNonce() {
	key := HashByteSecret([]byte("key"))
	ciphertext, _, err := AesEncrypt(key, "test")
	s.Require().NoError(err)

	badNonce := make([]byte, 12)
	_, err = AesDecrypt(key, badNonce, ciphertext)
	s.Error(err)
}

func (s *EncryptionTestSuite) TestAesEncrypt_InvalidKeyLength() {
	_, _, err := AesEncrypt([]byte("short"), "test")
	s.Error(err)
}

func (s *EncryptionTestSuite) TestAesEncrypt_UniqueNonces() {
	key := HashByteSecret([]byte("key"))
	_, nonce1, err := AesEncrypt(key, "test")
	s.Require().NoError(err)

	_, nonce2, err := AesEncrypt(key, "test")
	s.Require().NoError(err)

	s.NotEqual(nonce1, nonce2, "each encryption should produce a unique nonce")
}

func TestEncryption(t *testing.T) {
	suite.Run(t, new(EncryptionTestSuite))
}
