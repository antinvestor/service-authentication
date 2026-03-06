package utils

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type GenerateTestSuite struct {
	suite.Suite
}

func (s *GenerateTestSuite) TestGenerateRandomString() {
	result, err := GenerateRandomString(16)
	s.Require().NoError(err)
	s.Len(result, 16)
}

func (s *GenerateTestSuite) TestGenerateRandomString_Zero() {
	result, err := GenerateRandomString(0)
	s.Require().NoError(err)
	s.Empty(result)
}

func (s *GenerateTestSuite) TestGenerateRandomBytes() {
	result, err := GenerateRandomBytes(32)
	s.Require().NoError(err)
	s.Len(result, 32)
}

func (s *GenerateTestSuite) TestGenerateRandomBytes_Unique() {
	b1, err := GenerateRandomBytes(16)
	s.Require().NoError(err)
	b2, err := GenerateRandomBytes(16)
	s.Require().NoError(err)
	s.NotEqual(b1, b2, "random bytes should be unique")
}

func (s *GenerateTestSuite) TestGenerateRandomStringEfficient() {
	result := GenerateRandomStringEfficient(20)
	s.Len(result, 20)

	// All characters should be from letterBytes
	for _, c := range result {
		s.Contains(letterBytes, string(c))
	}
}

func (s *GenerateTestSuite) TestGenerateRandomStringEfficient_DifferentLengths() {
	for _, length := range []int{1, 5, 10, 50, 100} {
		result := GenerateRandomStringEfficient(length)
		s.Len(result, length)
	}
}

func TestGenerate(t *testing.T) {
	suite.Run(t, new(GenerateTestSuite))
}
