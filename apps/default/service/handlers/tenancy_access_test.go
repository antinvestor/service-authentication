package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
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
	s.True(partitionAllowsAutoAccess(&partitionv1.PartitionObject{}))
}

func (s *TenancyAccessTestSuite) TestPartitionAllowsAutoAccess_ReadsProperties() {
	props, err := structpb.NewStruct(map[string]any{
		partitionpolicy.PropertyAllowAutoAccess: false,
	})
	s.Require().NoError(err)

	s.False(partitionAllowsAutoAccess(&partitionv1.PartitionObject{Properties: props}))
}

func (s *TenancyAccessTestSuite) TestPartitionAccessRequestURI_FallbackKey() {
	props, err := structpb.NewStruct(map[string]any{
		partitionpolicy.PropertyAccessInstructionsURI: "https://members.example.com/join",
	})
	s.Require().NoError(err)

	s.Equal("https://members.example.com/join", partitionAccessRequestURI(&partitionv1.PartitionObject{Properties: props}))
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
