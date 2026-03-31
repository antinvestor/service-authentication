package events

import (
	"context"
	"errors"
	"fmt"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/data"
	fevents "github.com/pitabwire/frame/events"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
)

const EventKeyAuthzPartitionSync = "authorization.partition.sync"

// AuthzPartitionSyncEvent writes authorization tuples to Keto after a partition
// is created or synced. This is separate from the Hydra sync event so that
// authorization concerns are decoupled from OAuth2 client management.
//
// For every child partition it writes inheritance tuples (member + service) and
// bridge tuples for namespaces derived from all parent partition SAs' audiences.
type AuthzPartitionSyncEvent struct {
	partitionRepo      repository.PartitionRepository
	serviceAccountRepo repository.ServiceAccountRepository
	authorizer         security.Authorizer
}

func NewAuthzPartitionSyncEventHandler(
	partitionRepo repository.PartitionRepository,
	serviceAccountRepo repository.ServiceAccountRepository,
	auth security.Authorizer,
) fevents.EventI {
	return &AuthzPartitionSyncEvent{
		partitionRepo:      partitionRepo,
		serviceAccountRepo: serviceAccountRepo,
		authorizer:         auth,
	}
}

func (e *AuthzPartitionSyncEvent) Name() string {
	return EventKeyAuthzPartitionSync
}

func (e *AuthzPartitionSyncEvent) PayloadType() any {
	var payloadT map[string]any
	return &payloadT
}

func (e *AuthzPartitionSyncEvent) Validate(_ context.Context, payload any) error {
	d, ok := payload.(*map[string]any)
	if !ok {
		return fmt.Errorf("invalid payload type, expected *map[string]any got %T", payload)
	}
	m := data.JSONMap(*d)
	if m.GetString("id") == "" {
		return errors.New("partition id is required")
	}
	return nil
}

func (e *AuthzPartitionSyncEvent) Execute(ictx context.Context, payload any) error {
	d, ok := payload.(*map[string]any)
	if !ok {
		return fmt.Errorf("invalid payload type, expected *map[string]any got %T", payload)
	}

	jsonPayload := data.JSONMap(*d)
	ctx := security.SkipTenancyChecksOnClaims(ictx)

	partitionID := jsonPayload.GetString("id")
	logger := util.Log(ctx).WithFields(map[string]any{
		"partition_id": partitionID,
		"type":         e.Name(),
	})

	partition, err := e.partitionRepo.GetByID(ctx, partitionID)
	if err != nil {
		return fmt.Errorf("failed to get partition %s: %w", partitionID, err)
	}

	tenancyPath := fmt.Sprintf("%s/%s", partition.TenantID, partition.GetID())

	logger.WithField("tenancy_path", tenancyPath).
		Debug("partition authz sync processed")

	// Write partition inheritance tuple if this partition has a parent.
	// This creates a Keto subject set so members of the parent partition
	// automatically get access to the child partition.
	if partition.ParentID == "" {
		return nil
	}

	parentPartition, err := e.partitionRepo.GetByID(ctx, partition.ParentID)
	if err != nil {
		return fmt.Errorf("failed to get parent partition %s: %w", partition.ParentID, err)
	}

	parentPath := fmt.Sprintf("%s/%s", parentPartition.TenantID, parentPartition.GetID())
	memberTuple := authz.BuildPartitionInheritanceTuple(parentPath, tenancyPath)

	if writeErr := e.authorizer.WriteTuple(ctx, memberTuple); writeErr != nil {
		return fmt.Errorf("failed to write partition inheritance tuple: %w", writeErr)
	}

	// Write service inheritance tuple so service bots registered on the parent
	// partition automatically get service access to the child partition.
	serviceTuple := authz.BuildServicePartitionInheritanceTuple(parentPath, tenancyPath)
	if writeErr := e.authorizer.WriteTuple(ctx, serviceTuple); writeErr != nil {
		return fmt.Errorf("failed to write service partition inheritance tuple: %w", writeErr)
	}

	// Collect namespaces from all SAs on the parent partition — SA audiences
	// are the only source of truth for which namespaces need bridge tuples.
	parentSAs, err := e.serviceAccountRepo.ListByPartition(ctx, partition.ParentID)
	if err != nil {
		return fmt.Errorf("failed to list parent partition SAs: %w", err)
	}

	nsSet := make(map[string]bool)
	for _, sa := range parentSAs {
		for _, ns := range authz.AudienceNamespaces(sa.Audiences) {
			nsSet[ns] = true
		}
	}

	if len(nsSet) > 0 {
		namespaces := make([]string, 0, len(nsSet))
		for ns := range nsSet {
			namespaces = append(namespaces, ns)
		}

		bridgeTuples := authz.BuildServiceInheritanceTuples(tenancyPath, namespaces)
		if writeErr := e.authorizer.WriteTuples(ctx, bridgeTuples); writeErr != nil {
			return fmt.Errorf("failed to write service namespace bridge tuples: %w", writeErr)
		}

		logger.WithFields(map[string]any{
			"parent_path":     parentPath,
			"child_path":      tenancyPath,
			"bridge_ns_count": len(bridgeTuples),
		}).Debug("wrote partition inheritance and namespace bridge tuples")
	} else {
		logger.WithFields(map[string]any{
			"parent_path": parentPath,
			"child_path":  tenancyPath,
		}).Debug("wrote partition and service inheritance tuples")
	}

	return nil
}
