package handlers

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type ConsentHelpersTestSuite struct {
	suite.Suite
}

// --- extractLoginEventID ---

func (s *ConsentHelpersTestSuite) TestExtractLoginEventID_Valid() {
	ctx := map[string]any{"login_event_id": "evt-123"}
	s.Equal("evt-123", extractLoginEventID(ctx))
}

func (s *ConsentHelpersTestSuite) TestExtractLoginEventID_Missing() {
	s.Equal("", extractLoginEventID(map[string]any{}))
}

func (s *ConsentHelpersTestSuite) TestExtractLoginEventID_NotMap() {
	s.Equal("", extractLoginEventID("not-a-map"))
	s.Equal("", extractLoginEventID(nil))
}

func (s *ConsentHelpersTestSuite) TestExtractLoginEventID_NotString() {
	ctx := map[string]any{"login_event_id": 123}
	s.Equal("", extractLoginEventID(ctx))
}

// --- inferDeviceName ---

func (s *ConsentHelpersTestSuite) TestInferDeviceName_Empty() {
	s.Equal("Unknown Client", inferDeviceName(""))
}

func (s *ConsentHelpersTestSuite) TestInferDeviceName_Flutter() {
	s.Equal("Mobile App (Flutter)", inferDeviceName("Dart/2.19 (flutter)"))
}

func (s *ConsentHelpersTestSuite) TestInferDeviceName_Android() {
	s.Equal("Mobile App (Android)", inferDeviceName("okhttp/4.10.0"))
}

func (s *ConsentHelpersTestSuite) TestInferDeviceName_iOS() {
	s.Equal("Mobile App (iOS)", inferDeviceName("CFNetwork/1408.0 Darwin/22.5.0"))
}

func (s *ConsentHelpersTestSuite) TestInferDeviceName_Python() {
	s.Equal("API Client (Python)", inferDeviceName("python-requests/2.28"))
}

func (s *ConsentHelpersTestSuite) TestInferDeviceName_Go() {
	s.Equal("API Client (Go)", inferDeviceName("Go-http-client/2.0"))
}

func (s *ConsentHelpersTestSuite) TestInferDeviceName_Node() {
	s.Equal("API Client (Node)", inferDeviceName("node-fetch/3.0"))
}

func (s *ConsentHelpersTestSuite) TestInferDeviceName_Curl() {
	s.Equal("API Client (cURL)", inferDeviceName("curl/7.88.1"))
}

func (s *ConsentHelpersTestSuite) TestInferDeviceName_Postman() {
	s.Equal("API Client (Postman)", inferDeviceName("PostmanRuntime/7.32"))
}

func (s *ConsentHelpersTestSuite) TestInferDeviceName_Bot() {
	s.Equal("Bot", inferDeviceName("Googlebot/2.1"))
}

func (s *ConsentHelpersTestSuite) TestInferDeviceName_Browser() {
	s.Equal("Web Browser", inferDeviceName("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120"))
}

func (s *ConsentHelpersTestSuite) TestInferDeviceName_Unknown() {
	s.Equal("API Client", inferDeviceName("some-custom-agent"))
}

func TestConsentHelpers(t *testing.T) {
	suite.Run(t, new(ConsentHelpersTestSuite))
}
