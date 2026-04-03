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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStaticServiceProfileMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		clientID  string
		profileID string
		found     bool
	}{
		{"service-authentication", "d75qclkpf2t1uum8ij40", true},
		{"service-profile", "d75qclkpf2t1uum8ij4g", true},
		{"service-tenancy", "d75qclkpf2t1uum8ij50", true},
		{"service-notification", "d75qclkpf2t1uum8ij5g", true},
		{"service-device", "d75qclkpf2t1uum8ij60", true},
		{"foundry", "d75qclkpf2t1uum8ijag", true},
		{"gitvault", "d75qclkpf2t1uum8ijb0", true},
		{"trustage", "d75qclkpf2t1uum8ijbg", true},
		{"unknown-service", "", false},
		{"", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.clientID, func(t *testing.T) {
			t.Parallel()
			id, ok := staticServiceProfiles[tt.clientID]
			require.Equal(t, tt.found, ok)
			if ok {
				require.Equal(t, tt.profileID, id)
			}
		})
	}
}

func TestIsPlaceholderProfileID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		profileID     string
		isPlaceholder bool
	}{
		{"empty", "", true},
		{"old placeholder service_authentication", "service_authentication", true},
		{"old placeholder service_notification", "service_notification", true},
		{"old placeholder foundry", "foundry", true},
		{"old placeholder trustage", "trustage", true},
		{"real xid 1", "c2f4j7au6s7f91uqnolg", false},
		{"real xid 2", "9bsv0s3pbdv002o80qhg", false},
		{"bootstrap xid", "d75qclkpf2t1uum8ij40", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.isPlaceholder, isPlaceholderProfileID(tt.profileID))
		})
	}
}
