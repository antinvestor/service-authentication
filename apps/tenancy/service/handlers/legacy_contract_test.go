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

	tenancyv1 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v1"
	"connectrpc.com/connect"
)

func TestLegacyAuthContractMethodsAreUnimplemented(t *testing.T) {
	t.Parallel()
	server := &TenancyServer{}

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "create client",
			call: func() error {
				_, err := server.CreateClient(context.Background(), connect.NewRequest(&tenancyv1.CreateClientRequest{}))
				return err
			},
		},
		{
			name: "create service account",
			call: func() error {
				_, err := server.CreateServiceAccount(context.Background(), connect.NewRequest(&tenancyv1.CreateServiceAccountRequest{}))
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if code := connect.CodeOf(test.call()); code != connect.CodeUnimplemented {
				t.Fatalf("expected unimplemented, got %s", code)
			}
		})
	}
}
