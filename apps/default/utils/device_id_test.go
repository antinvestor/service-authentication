package utils

import (
	"context"
	"testing"

	"github.com/stretchr/testify/suite"
)

type DeviceIDTestSuite struct {
	suite.Suite
}

func (s *DeviceIDTestSuite) TestDeviceIDRoundTrip() {
	ctx := context.Background()
	ctx = DeviceIDToContext(ctx, "device-123")
	s.Equal("device-123", DeviceIDFromContext(ctx))
}

func (s *DeviceIDTestSuite) TestDeviceIDFromContext_Empty() {
	ctx := context.Background()
	s.Equal("", DeviceIDFromContext(ctx))
}

func (s *DeviceIDTestSuite) TestDeviceIDToContext_Overwrite() {
	ctx := context.Background()
	ctx = DeviceIDToContext(ctx, "first")
	ctx = DeviceIDToContext(ctx, "second")
	s.Equal("second", DeviceIDFromContext(ctx))
}

func (s *DeviceIDTestSuite) TestSessionIDRoundTrip() {
	ctx := context.Background()
	ctx = SessionIDToContext(ctx, "session-456")
	s.Equal("session-456", SessionIDFromContext(ctx))
}

func (s *DeviceIDTestSuite) TestSessionIDFromContext_Empty() {
	ctx := context.Background()
	s.Equal("", SessionIDFromContext(ctx))
}

func (s *DeviceIDTestSuite) TestSessionIDToContext_Overwrite() {
	ctx := context.Background()
	ctx = SessionIDToContext(ctx, "first")
	ctx = SessionIDToContext(ctx, "second")
	s.Equal("second", SessionIDFromContext(ctx))
}

func (s *DeviceIDTestSuite) TestDeviceAndSessionIndependent() {
	ctx := context.Background()
	ctx = DeviceIDToContext(ctx, "device-1")
	ctx = SessionIDToContext(ctx, "session-1")
	s.Equal("device-1", DeviceIDFromContext(ctx))
	s.Equal("session-1", SessionIDFromContext(ctx))
}

func (s *DeviceIDTestSuite) TestContextKeyString() {
	s.Equal("authentication/deviceKey", ctxKeyDevice.String())
	s.Equal("authentication/sessionKey", ctxKeySession.String())
}

func TestDeviceID(t *testing.T) {
	suite.Run(t, new(DeviceIDTestSuite))
}
