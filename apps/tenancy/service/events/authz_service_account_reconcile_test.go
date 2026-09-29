package events

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/v2/data"
	"github.com/pitabwire/frame/v2/queue/push"
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

	reconciler := NewAuthzServiceAccountSyncEventHandler(nil, nil, nil, nil, nil, nil, nil)
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

// A reconcile whose push delivery ends while it waits for capacity must fail
// with a retryable error so Pub/Sub redelivers it (service-authentication#855):
// an ack here would silently drop the policy until the hourly re-queue.
func TestCancelledDeliveryWaitingForCapacityIsRedelivered(t *testing.T) {
	t.Parallel()

	reconciler := NewAuthzServiceAccountSyncEventHandler(nil, nil, nil, nil, nil, nil, nil)
	for range maxConcurrentAuthorizationReconciliations {
		require.NoError(t, reconciler.acquire(t.Context()))
	}
	t.Cleanup(func() {
		for range maxConcurrentAuthorizationReconciliations {
			reconciler.release()
		}
	})

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	payload := &map[string]any{"id": "sa-id", "generation": int64(1)}
	err := reconciler.Execute(ctx, payload)

	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, http.StatusServiceUnavailable, push.HTTPStatusFor(err))
}

func TestMissingPolicyNamespacesAreDeferredUntilRegistration(t *testing.T) {
	t.Parallel()

	missing := missingPolicyNamespaces([]repository.AuthorizationGrant{
		{Namespace: "service_records"},
		{Namespace: "service_profile"},
		{Namespace: "service_records"},
	}, map[string]struct{}{"service_profile": {}})

	require.Equal(t, []string{"service_records"}, missing)
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
