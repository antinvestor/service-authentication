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

package business

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizePermissionManifest(t *testing.T) {
	t.Parallel()

	valid, err := normalizePermissionManifest(PermissionManifest{
		Namespace:   " service_records ",
		Permissions: []string{"record_view", "record_manage", "record_view"},
		RoleBindings: map[string][]string{
			"service": {"record_view", "record_manage"},
		},
	})
	require.NoError(t, err)
	require.Equal(t, "service_records", valid.Namespace)
	require.Equal(t, "platform", valid.Domain)
	require.Equal(t, []string{"record_manage", "record_view"}, valid.Permissions)
	require.Equal(t, []string{"record_manage", "record_view"}, valid.RoleBindings["service"])

	tests := []struct {
		name     string
		manifest PermissionManifest
	}{
		{
			name:     "invalid namespace",
			manifest: PermissionManifest{Namespace: "Records", Permissions: []string{"record_view"}},
		},
		{
			name:     "wildcard permission",
			manifest: PermissionManifest{Namespace: "service_records", Permissions: []string{"*"}},
		},
		{
			name:     "empty permissions",
			manifest: PermissionManifest{Namespace: "service_records"},
		},
		{
			name: "unknown role",
			manifest: PermissionManifest{
				Namespace: "service_records", Permissions: []string{"record_view"},
				RoleBindings: map[string][]string{"superuser": {"record_view"}},
			},
		},
		{
			name: "undeclared role permission",
			manifest: PermissionManifest{
				Namespace: "service_records", Permissions: []string{"record_view"},
				RoleBindings: map[string][]string{"service": {"record_manage"}},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, testErr := normalizePermissionManifest(test.manifest)
			require.ErrorIs(t, testErr, ErrInvalidPermissionManifest)
		})
	}
}
