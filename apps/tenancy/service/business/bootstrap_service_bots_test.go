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

	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/stretchr/testify/require"
)

func TestServiceBotAccessTupleShapes(t *testing.T) {
	t.Parallel()

	saProfile := "d75qclkpf2t1uum8ij40"
	rootPath := authz.RootTenantID + "/" + authz.RootPartitionID
	childPath := "d7gi6lkpf2t67dlsqre0/d7gi6lkpf2t67dlsqreg"

	t1 := authz.BuildServiceAccessTuple(rootPath, saProfile)
	require.Equal(t, authz.NamespaceTenancyAccess, t1.Object.Namespace)
	require.Equal(t, rootPath, t1.Object.ID)
	require.Equal(t, authz.RoleService, t1.Relation)
	require.Equal(t, authz.NamespaceProfile, t1.Subject.Namespace)
	require.Equal(t, saProfile, t1.Subject.ID)

	t2 := authz.BuildServicePartitionInheritanceTuple(rootPath, childPath)
	require.Equal(t, authz.NamespaceTenancyAccess, t2.Object.Namespace)
	require.Equal(t, childPath, t2.Object.ID)
	require.Equal(t, authz.RoleService, t2.Relation)
	require.Equal(t, authz.NamespaceTenancyAccess, t2.Subject.Namespace)
	require.Equal(t, rootPath, t2.Subject.ID)
	require.Equal(t, authz.RoleService, t2.Subject.Relation)
}
