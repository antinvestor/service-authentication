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
