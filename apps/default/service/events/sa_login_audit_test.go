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

package events

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServiceAccountLoginAuditEvent_Validate(t *testing.T) {
	t.Parallel()
	h := NewServiceAccountLoginAuditEventHandler(nil, nil)

	tests := []struct {
		name    string
		payload any
		wantErr bool
	}{
		{
			name: "valid",
			payload: &ServiceAccountLoginAuditPayload{
				LoginEventID: "sa_sess_c1",
				ClientID:     "c1",
				ProfileID:    "p1",
			},
			wantErr: false,
		},
		{
			name:    "wrong type",
			payload: map[string]any{},
			wantErr: true,
		},
		{
			name: "missing fields",
			payload: &ServiceAccountLoginAuditPayload{
				LoginEventID: "sa_sess_c1",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := h.Validate(context.Background(), tt.payload)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestServiceAccountLoginAuditEvent_NameAndPayloadType(t *testing.T) {
	t.Parallel()
	h := NewServiceAccountLoginAuditEventHandler(nil, nil)
	require.Equal(t, EventKeyServiceAccountLoginAudit, h.Name())
	_, ok := h.PayloadType().(*ServiceAccountLoginAuditPayload)
	require.True(t, ok)
}
