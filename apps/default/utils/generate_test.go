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
