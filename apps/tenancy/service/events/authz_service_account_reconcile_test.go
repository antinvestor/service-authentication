package events

import (
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/stretchr/testify/require"
)

func TestDiffAuthorizationTuplesDeletesRevokedAndWritesNew(t *testing.T) {
	t.Parallel()

	applied := []*models.ServiceAccountAppliedTuple{
		{
			Namespace: "service_profile", Object: "tenant/partition", Relation: "granted_profile_view",
			SubjectNamespace: "profile_user", SubjectObject: "bot-profile",
		},
		{
			Namespace: "service_profile", Object: "tenant/partition", Relation: "granted_profile_update",
			SubjectNamespace: "profile_user", SubjectObject: "bot-profile",
		},
	}
	desired := []*models.ServiceAccountAppliedTuple{
		{
			Namespace: "service_profile", Object: "tenant/partition", Relation: "granted_profile_view",
			SubjectNamespace: "profile_user", SubjectObject: "bot-profile",
		},
		{
			Namespace: "service_tenancy", Object: "tenant/partition", Relation: "granted_partition_view",
			SubjectNamespace: "profile_user", SubjectObject: "bot-profile",
		},
	}

	deletes, writes := diffAuthorizationTuples(applied, desired)
	require.Len(t, deletes, 1)
	require.Equal(t, "granted_profile_update", deletes[0].Relation)
	require.Len(t, writes, 1)
	require.Equal(t, "service_tenancy", writes[0].Object.Namespace)
	require.Equal(t, "granted_partition_view", writes[0].Relation)
}
