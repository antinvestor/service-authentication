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
// For every partition it writes bridge tuples for the service_tenancy namespace
// so that service bots can access the partition service. For partitions with a
// parent, it also writes an inheritance tuple so members of the parent get
// automatic access to the child.
type AuthzPartitionSyncEvent struct {
	partitionRepo repository.PartitionRepository
	authorizer    security.Authorizer
}

func NewAuthzPartitionSyncEventHandler(partitionRepo repository.PartitionRepository, auth security.Authorizer) fevents.EventI {
	return &AuthzPartitionSyncEvent{
		partitionRepo: partitionRepo,
		authorizer:    auth,
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
	logger := util.Log(ctx).
		WithField("partition_id", partitionID).
		WithField("type", e.Name())

	partition, err := e.partitionRepo.GetByID(ctx, partitionID)
	if err != nil {
		return fmt.Errorf("failed to get partition %s: %w", partitionID, err)
	}

	tenancyPath := fmt.Sprintf("%s/%s", partition.TenantID, partition.GetID())

	// Write bridge tuples for all service namespaces so service bots with a
	// single tenancy_access:path#service tuple get functional permissions in
	// every service. Each bridge creates the subject set chain:
	//   tenancy_access:path#service → ns:path#service → OPL permits
	bridgeTuples := authz.BuildServiceInheritanceTuples(tenancyPath, authz.AllServiceNamespaces)
	if writeErr := e.authorizer.WriteTuples(ctx, bridgeTuples); writeErr != nil {
		return fmt.Errorf("failed to write service bridge tuples: %w", writeErr)
	}

	logger.WithField("tenancy_path", tenancyPath).
		WithField("namespaces", len(authz.AllServiceNamespaces)).
		Info("wrote service bridge tuples for all namespaces")

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

	logger.
		WithField("parent_path", parentPath).
		WithField("child_path", tenancyPath).
		Info("wrote partition inheritance and service inheritance tuples")

	return nil
}
