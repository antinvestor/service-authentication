package events

import (
	"context"
	"errors"
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/v2/data"
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

func TestAuthorizationReconciliationConcurrencyIsBounded(t *testing.T) {
	t.Parallel()

	reconciler := NewAuthzServiceAccountSyncEventHandler(nil, nil, nil, nil, nil, nil)
	for range maxConcurrentAuthorizationReconciliations {
		require.NoError(t, reconciler.acquire(t.Context()))
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := reconciler.acquire(ctx)
	require.Error(t, err)
	require.True(t, errors.Is(err, context.Canceled))

	for range maxConcurrentAuthorizationReconciliations {
		reconciler.release()
	}
}

func TestBuildPartitionTreeUsesStructuralAncestryAcrossTenantBoundaries(t *testing.T) {
	t.Parallel()

	partition := func(id, tenantID string) *models.Partition {
		return &models.Partition{BaseModel: data.BaseModel{ID: id, TenantID: tenantID}}
	}
	root := partition("platform", "platform-tenant")
	product := partition("product", "product-tenant")
	environment := partition("environment", "product-tenant")
	unrelated := partition("unrelated", "unrelated-tenant")
	children := map[string][]*models.Partition{
		root.ID:    {product},
		product.ID: {environment},
		unrelated.ID: {
			partition("unrelated-child", "unrelated-tenant"),
		},
	}

	tree, err := buildPartitionTree(t.Context(), root, func(_ context.Context, id string) ([]*models.Partition, error) {
		return children[id], nil
	})
	require.NoError(t, err)
	require.Equal(t, []string{"environment", "platform", "product"}, []string{tree[0].ID, tree[1].ID, tree[2].ID})
	require.NotContains(t, tree, unrelated)
}
