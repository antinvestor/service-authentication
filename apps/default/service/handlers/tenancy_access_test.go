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

package handlers

import (
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"testing"

	tenancyv1 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v1"
	"github.com/antinvestor/service-authentication/pkg/partitionpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/types/known/structpb"
)

type TenancyAccessTestSuite struct {
	suite.Suite
}

func TestTenancyAccess(t *testing.T) {
	suite.Run(t, new(TenancyAccessTestSuite))
}

func (s *TenancyAccessTestSuite) TestPartitionAllowsAutoAccess_DefaultsTrue() {
	s.True(partitionAllowsAutoAccess(&tenancyv1.PartitionObject{}))
}

func (s *TenancyAccessTestSuite) TestPartitionAllowsAutoAccess_ReadsProperties() {
	props, err := structpb.NewStruct(map[string]any{
		partitionpolicy.PropertyAllowAutoAccess: false,
	})
	s.Require().NoError(err)

	s.False(partitionAllowsAutoAccess(&tenancyv1.PartitionObject{Properties: props}))
}

func (s *TenancyAccessTestSuite) TestPartitionAccessRequestURI_FallbackKey() {
	props, err := structpb.NewStruct(map[string]any{
		partitionpolicy.PropertyAccessInstructionsURI: "https://members.example.com/join",
	})
	s.Require().NoError(err)

	s.Equal("https://members.example.com/join", partitionAccessRequestURI(&tenancyv1.PartitionObject{Properties: props}))
}

func (s *TenancyAccessTestSuite) TestRedirectToErrorPage_AccessInstructions() {
	server := &AuthServer{}
	req := httptest.NewRequest(http.MethodGet, "/s/login", nil)
	recorder := httptest.NewRecorder()

	server.redirectToErrorPage(recorder, req, &accessInstructionsRedirectError{
		URI: "https://members.example.com/request-access",
	}, "LoginEndpointShow")

	response := recorder.Result()
	defer response.Body.Close()

	assert.Equal(s.T(), http.StatusSeeOther, response.StatusCode)
	assert.Equal(s.T(), "https://members.example.com/request-access", response.Header.Get("Location"))
}

func (s *TenancyAccessTestSuite) TestRedirectToErrorPage_DefaultAccessInstructionsPage() {
	server := &AuthServer{}
	req := httptest.NewRequest(http.MethodGet, "/s/login?ui_locales=en", nil)
	recorder := httptest.NewRecorder()

	server.redirectToErrorPage(recorder, req, &accessInstructionsRedirectError{
		PartitionName: "Members Only",
		SupportContacts: map[string]string{
			"email":  "members@example.com",
			"msisdn": "+256700000000",
		},
	}, "LoginEndpointShow")

	response := recorder.Result()
	defer response.Body.Close()

	redirectLocation := response.Header.Get("Location")
	parsedLocation, err := neturl.Parse(redirectLocation)
	s.Require().NoError(err)

	assert.Equal(s.T(), http.StatusSeeOther, response.StatusCode)
	assert.Equal(s.T(), accessInstructionsPath, parsedLocation.Path)
	assert.Equal(s.T(), "Members Only", parsedLocation.Query().Get("partition_name"))
	assert.NotEmpty(s.T(), parsedLocation.Query().Get("support_contacts"))
}
