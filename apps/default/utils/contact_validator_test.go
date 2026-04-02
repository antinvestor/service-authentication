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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type ContactValidatorTestSuite struct {
	suite.Suite
}

func (s *ContactValidatorTestSuite) TestIsEmail_Valid() {
	cases := []string{
		"user@example.com",
		"test.user@domain.co.uk",
		"a+b@example.org",
		"user123@sub.domain.io",
		"first.last@company.com",
	}
	for _, email := range cases {
		s.True(IsEmail(email), "expected %q to be a valid email", email)
	}
}

func (s *ContactValidatorTestSuite) TestIsEmail_Invalid() {
	cases := []string{
		"",
		"notanemail",
		"@example.com",
		"user@",
		"user@.com",
		"user@com",
		"+1234567890",
		"user @example.com",
	}
	for _, email := range cases {
		s.False(IsEmail(email), "expected %q to be an invalid email", email)
	}
}

func (s *ContactValidatorTestSuite) TestIsEmail_WithWhitespace() {
	// IsEmail trims spaces
	assert.True(s.T(), IsEmail(" user@example.com "))
}

func (s *ContactValidatorTestSuite) TestIsPhoneNumber_Valid() {
	cases := []string{
		"+1234567890",
		"1234567890",
		"+1 (234) 567-8901",
		"123-456-7890",
		"1234567",          // minimum 7 digits
		"123456789012345",  // maximum 15 digits
		"+44 20 7946 0958", // UK format
		"(555) 123-4567",   // US format
		"+254.722.000.000", // dot-separated
	}
	for _, phone := range cases {
		s.True(IsPhoneNumber(phone), "expected %q to be a valid phone number", phone)
	}
}

func (s *ContactValidatorTestSuite) TestIsPhoneNumber_Invalid() {
	cases := []string{
		"",
		"123456",           // too short (6 digits)
		"1234567890123456", // too long (16 digits)
		"abcdefghij",       // letters
		"123-abc-7890",     // mixed
		"user@example.com", // email
	}
	for _, phone := range cases {
		s.False(IsPhoneNumber(phone), "expected %q to be an invalid phone number", phone)
	}
}

func (s *ContactValidatorTestSuite) TestGetContactType() {
	s.Equal(ContactTypeEmail, GetContactType("user@example.com"))
	s.Equal(ContactTypePhone, GetContactType("+1234567890"))
	s.Equal(ContactTypeUnknown, GetContactType(""))
	s.Equal(ContactTypeUnknown, GetContactType("invalid"))
}

func (s *ContactValidatorTestSuite) TestGetContactType_TrimsWhitespace() {
	s.Equal(ContactTypeEmail, GetContactType("  user@example.com  "))
}

func (s *ContactValidatorTestSuite) TestValidateContact() {
	ct, valid := ValidateContact("user@example.com")
	s.True(valid)
	s.Equal(ContactTypeEmail, ct)

	ct, valid = ValidateContact("+1234567890")
	s.True(valid)
	s.Equal(ContactTypePhone, ct)

	ct, valid = ValidateContact("")
	s.False(valid)
	s.Equal(ContactTypeUnknown, ct)

	ct, valid = ValidateContact("garbage")
	s.False(valid)
	s.Equal(ContactTypeUnknown, ct)
}

func (s *ContactValidatorTestSuite) TestContactType_String() {
	s.Equal("email", ContactTypeEmail.String())
	s.Equal("phone", ContactTypePhone.String())
	s.Equal("unknown", ContactTypeUnknown.String())
	s.Equal("unknown", ContactType(99).String())
}

func TestContactValidator(t *testing.T) {
	suite.Run(t, new(ContactValidatorTestSuite))
}
