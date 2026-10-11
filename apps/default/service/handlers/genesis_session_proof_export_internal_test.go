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
	"context"
	"testing"
)

// NewGenesisProofServerForTest exposes a configured proof server to the
// external test package, which drives it through the generated Connect
// client. sessionDevice is the device the live login event belongs to.
func NewGenesisProofServerForTest(t *testing.T, sessionDevice string) *AuthServer {
	t.Helper()
	event := liveEvent()
	event.DeviceID = sessionDevice
	return proofServer(t, stubSessions{event: event})
}

// PersonContextForTest is a person's session on device-1.
func PersonContextForTest(t *testing.T) context.Context {
	t.Helper()
	return personContext(t, "login-event-1")
}
