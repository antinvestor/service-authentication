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
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/stretchr/testify/require"
)

func TestServiceAccountKetoSubjectPrefersClientID(t *testing.T) {
	t.Parallel()

	require.Equal(t, "service-authentication", serviceAccountKetoSubject(&models.ServiceAccount{
		ClientID:  "service-authentication",
		ProfileID: "d75qclkpf2t1uum8ij40",
	}))
	require.Equal(t, "d75qclkpf2t1uum8ij40", serviceAccountKetoSubject(&models.ServiceAccount{
		ProfileID: "d75qclkpf2t1uum8ij40",
	}))
	require.Equal(t, "", serviceAccountKetoSubject(nil))
	require.Equal(t, "", serviceAccountKetoSubject(&models.ServiceAccount{}))
}

func TestCollectServiceBotSubjectsIncludesClientAndProfile(t *testing.T) {
	t.Parallel()

	accounts := []*models.ServiceAccount{
		{ClientID: "service-authentication", ProfileID: "d75qclkpf2t1uum8ij40"},
		{ClientID: "service-profile", ProfileID: "d75qclkpf2t1uum8ij4g"},
		{ProfileID: "orphan-profile-only"},
		nil,
	}
	subjects, paths := collectServiceBotSubjectsAndPaths(accounts, nil)

	require.Contains(t, subjects, "service-authentication")
	require.Contains(t, subjects, "d75qclkpf2t1uum8ij40")
	require.Contains(t, subjects, "service-profile")
	require.Contains(t, subjects, "d75qclkpf2t1uum8ij4g")
	require.Contains(t, subjects, "orphan-profile-only")
	require.Contains(t, paths, authz.RootTenantID+"/"+authz.RootPartitionID)
}

func TestServiceBotAccessTupleShapes(t *testing.T) {
	t.Parallel()

	// JWT sub for client_credentials is the OAuth2 client_id.
	saSubject := "service-authentication"
	rootPath := authz.RootTenantID + "/" + authz.RootPartitionID
	childPath := "d7gi6lkpf2t67dlsqre0/d7gi6lkpf2t67dlsqreg"

	t1 := authz.BuildServiceAccessTuple(rootPath, saSubject)
	require.Equal(t, authz.NamespaceTenancyAccess, t1.Object.Namespace)
	require.Equal(t, rootPath, t1.Object.ID)
	require.Equal(t, authz.RoleService, t1.Relation)
	require.Equal(t, authz.NamespaceProfile, t1.Subject.Namespace)
	require.Equal(t, saSubject, t1.Subject.ID)

	t2 := authz.BuildServicePartitionInheritanceTuple(rootPath, childPath)
	require.Equal(t, authz.NamespaceTenancyAccess, t2.Object.Namespace)
	require.Equal(t, childPath, t2.Object.ID)
	require.Equal(t, authz.RoleService, t2.Relation)
	require.Equal(t, authz.NamespaceTenancyAccess, t2.Subject.Namespace)
	require.Equal(t, rootPath, t2.Subject.ID)
	require.Equal(t, authz.RoleService, t2.Subject.Relation)
}

func TestBuildServiceBotTenancyTuplesUsesClientSubjects(t *testing.T) {
	t.Parallel()

	subjects := map[string]struct{}{"service-authentication": {}}
	paths := map[string]struct{}{
		authz.RootTenantID + "/" + authz.RootPartitionID: {},
	}
	tuples := buildServiceBotTenancyTuples(subjects, paths, nil)
	require.Len(t, tuples, 1)
	require.Equal(t, "service-authentication", tuples[0].Subject.ID)
	require.Equal(t, authz.RoleService, tuples[0].Relation)
}
