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
	"errors"
	"fmt"
	"slices"
	"time"

	commonv1 "buf.build/gen/go/antinvestor/common/protocolbuffers/go/common/v1"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/v2/data"
	fevents "github.com/pitabwire/frame/v2/events"
	"github.com/pitabwire/frame/v2/security"
	"github.com/pitabwire/frame/v2/security/authorizer"
	"github.com/pitabwire/util"
	"google.golang.org/grpc/status"
)

const EventKeyAuthzServiceAccountSync = "authorization.service_account.sync"

const maxConcurrentAuthorizationReconciliations = 4

// AuthzServiceAccountSyncEvent reconciles exact Keto state from the normalised
// authorization policy. Events carry a generation and are only a latency
// mechanism; the policy and applied-tuple rows remain authoritative.
type AuthzServiceAccountSyncEvent struct {
	serviceAccountRepo   repository.ServiceAccountRepository
	partitionRepo        repository.PartitionRepository
	policyRepo           repository.ServiceAccountAuthorizationPolicyRepository
	serviceNamespaceRepo repository.ServiceNamespaceRepository
	authContractRepo     repository.AuthContractRepository
	eventsMan            fevents.Manager
	authorizer           security.Authorizer
	concurrency          chan struct{}
}

func NewAuthzServiceAccountSyncEventHandler(
	serviceAccountRepo repository.ServiceAccountRepository,
	partitionRepo repository.PartitionRepository,
	policyRepo repository.ServiceAccountAuthorizationPolicyRepository,
	serviceNamespaceRepo repository.ServiceNamespaceRepository,
	authContractRepo repository.AuthContractRepository,
	eventsMan fevents.Manager,
	auth security.Authorizer,
) *AuthzServiceAccountSyncEvent {
	return &AuthzServiceAccountSyncEvent{
		serviceAccountRepo:   serviceAccountRepo,
		partitionRepo:        partitionRepo,
		policyRepo:           policyRepo,
		serviceNamespaceRepo: serviceNamespaceRepo,
		authContractRepo:     authContractRepo,
		eventsMan:            eventsMan,
		authorizer:           auth,
		concurrency:          make(chan struct{}, maxConcurrentAuthorizationReconciliations),
	}
}

// ReconcilePending synchronously materialises every policy whose desired
// generation has not been applied. Startup calls this before serving traffic,
// so missing Keto schema or stale derived state fails closed and self-heals on
// the next restart after the dependency is corrected.
func (e *AuthzServiceAccountSyncEvent) ReconcilePending(ctx context.Context) error {
	namespaces, err := e.serviceNamespaceRepo.ListAll(ctx)
	if err != nil {
		return fmt.Errorf("list registered permission namespaces: %w", err)
	}
	registered := make(map[string]struct{}, len(namespaces))
	for _, namespace := range namespaces {
		registered[namespace.Namespace] = struct{}{}
	}

	policies, err := e.policyRepo.ListPending(ctx)
	if err != nil {
		return fmt.Errorf("list pending authorization policies: %w", err)
	}
	var failures []error
	for _, policy := range policies {
		state, stateErr := e.policyRepo.GetByServiceAccountID(ctx, policy.ServiceAccountID)
		if stateErr != nil {
			failures = append(failures, fmt.Errorf("load service account %s policy: %w", policy.ServiceAccountID, stateErr))
			continue
		}
		missing := missingPolicyNamespaces(state.Grants, registered)
		if len(missing) > 0 {
			util.Log(ctx).WithFields(map[string]any{
				"service_account_id": policy.ServiceAccountID,
				"namespaces":         missing,
			}).Info("authorization policy remains pending until service manifests register")
			continue
		}
		payload := map[string]any{
			"id":         policy.ServiceAccountID,
			"generation": policy.Generation,
			"reason":     "startup_reconciliation",
		}
		if err = e.Execute(ctx, &payload); err != nil {
			failures = append(failures, fmt.Errorf("reconcile service account %s policy: %w", policy.ServiceAccountID, err))
		}
	}
	return errors.Join(failures...)
}

func missingPolicyNamespaces(
	grants []repository.AuthorizationGrant,
	registered map[string]struct{},
) []string {
	missing := make([]string, 0)
	for _, grant := range grants {
		if _, ok := registered[grant.Namespace]; !ok {
			missing = append(missing, grant.Namespace)
		}
	}
	slices.Sort(missing)
	return slices.Compact(missing)
}

func (e *AuthzServiceAccountSyncEvent) Name() string {
	return EventKeyAuthzServiceAccountSync
}

func (e *AuthzServiceAccountSyncEvent) PayloadType() any {
	var payloadT map[string]any
	return &payloadT
}

func (e *AuthzServiceAccountSyncEvent) Validate(_ context.Context, payload any) error {
	d, ok := payload.(*map[string]any)
	if !ok {
		return fmt.Errorf("invalid payload type, expected *map[string]any got %T", payload)
	}
	m := data.JSONMap(*d)
	if m.GetString("id") == "" {
		return errors.New("service account id is required")
	}
	if authorizationPolicyGeneration(m) < 1 {
		return errors.New("authorization policy generation is required")
	}
	return nil
}

func (e *AuthzServiceAccountSyncEvent) Execute(ictx context.Context, payload any) error {
	d, ok := payload.(*map[string]any)
	if !ok {
		return fmt.Errorf("invalid payload type, expected *map[string]any got %T", payload)
	}

	jsonPayload := data.JSONMap(*d)
	ctx := security.SkipTenancyChecksOnClaims(ictx)
	ctx, cancel := withEventTimeout(ctx)
	defer cancel()
	if err := e.acquire(ctx); err != nil {
		return err
	}
	defer e.release()

	serviceAccountID := jsonPayload.GetString("id")
	eventGeneration := authorizationPolicyGeneration(jsonPayload)
	reason := jsonPayload.GetString("reason")
	logger := util.Log(ctx).WithFields(map[string]any{
		"service_account_id": serviceAccountID,
		"type":               e.Name(),
	})

	sa, err := e.serviceAccountRepo.GetByID(ctx, serviceAccountID)
	if err != nil {
		if isPermanentError(err) {
			logger.WithError(err).Warn("service account not found — skipping sync")
			return nil
		}
		return fmt.Errorf("failed to get service account %s: %w", serviceAccountID, err)
	}

	policyState, err := e.policyRepo.GetByServiceAccountID(ctx, serviceAccountID)
	if err != nil {
		return fmt.Errorf("load service account %s authorization policy: %w", serviceAccountID, err)
	}
	if eventGeneration < policyState.Policy.Generation {
		logger.WithFields(map[string]any{
			"event_generation":  eventGeneration,
			"policy_generation": policyState.Policy.Generation,
		}).Debug("stale authorization policy event ignored")
		return nil
	}
	if eventGeneration != policyState.Policy.Generation {
		return fmt.Errorf(
			"authorization policy generation %d does not exist for service account %s (current %d)",
			eventGeneration,
			serviceAccountID,
			policyState.Policy.Generation,
		)
	}

	desired, err := e.desiredTuples(ctx, sa, policyState.Grants)
	if err != nil {
		return e.handleFailure(ctx, policyState.Policy, reason, err)
	}
	applied, err := e.policyRepo.ListAppliedTuples(ctx, policyState.Policy.ID)
	if err != nil {
		return e.handleFailure(
			ctx,
			policyState.Policy,
			reason,
			fmt.Errorf("load applied authorization tuples: %w", err),
		)
	}

	deletes, writes := diffAuthorizationTuples(applied, desired)
	if len(deletes) > 0 {
		if err = writeTuplesWithRetry(ctx, e.Name(), func(ctx context.Context) error {
			return e.authorizer.DeleteTuples(ctx, deletes)
		}); err != nil {
			return e.handleFailure(ctx, policyState.Policy, reason, err)
		}
	}
	if len(writes) > 0 {
		if err = writeTuplesWithRetry(ctx, e.Name(), func(ctx context.Context) error {
			return e.authorizer.WriteTuples(ctx, writes)
		}); err != nil {
			return e.handleFailure(ctx, policyState.Policy, reason, err)
		}
	}

	if err = e.policyRepo.ReplaceAppliedState(ctx, policyState.Policy, desired); err != nil {
		return e.handleFailure(
			ctx,
			policyState.Policy,
			reason,
			fmt.Errorf("persist applied authorization state: %w", err),
		)
	}
	if sa.State == int32(commonv1.STATE_DELETED) {
		clientID, finalizeErr := e.authContractRepo.FinalizeServiceAccountRemoval(ctx, sa.ID)
		if finalizeErr != nil {
			return finalizeErr
		}
		if emitErr := e.eventsMan.Emit(ctx, EventKeyClientSynchronization, data.JSONMap{"id": clientID}); emitErr != nil {
			return fmt.Errorf("enqueue Hydra client removal: %w", emitErr)
		}
	}
	return nil
}

func authorizationPolicyGeneration(payload data.JSONMap) int64 {
	switch value := payload["generation"].(type) {
	case int:
		return int64(value)
	case int32:
		return int64(value)
	case int64:
		return value
	case uint:
		return int64(value)
	case uint32:
		return int64(value)
	case uint64:
		if value <= uint64(^uint64(0)>>1) {
			return int64(value)
		}
	case float32:
		generation := int64(value)
		if float32(generation) == value {
			return generation
		}
	case float64:
		generation := int64(value)
		if float64(generation) == value {
			return generation
		}
	}
	return 0
}

func (e *AuthzServiceAccountSyncEvent) handleFailure(
	ctx context.Context,
	policy *models.ServiceAccountAuthorizationPolicy,
	reason string,
	cause error,
) error {
	code := status.Code(cause).String()
	var serviceErr *authorizer.AuthzServiceError
	if errors.As(cause, &serviceErr) {
		code = serviceErr.Code.String()
		if serviceErr.SchemaReadiness {
			code = "schema_not_ready"
		}
	}
	message := cause.Error()
	if len(message) > 4096 {
		message = message[:4096]
	}
	recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	recordErr := e.policyRepo.RecordFailure(
		recordCtx,
		policy.ID,
		policy.Generation,
		code,
		message,
		time.Now().Add(time.Minute),
	)
	if recordErr != nil {
		return errors.Join(cause, fmt.Errorf("record authorization policy failure: %w", recordErr))
	}
	if reason != "startup_reconciliation" {
		logger := util.Log(ctx).WithError(cause).WithFields(map[string]any{
			"service_account_id": policy.ServiceAccountID,
			"generation":         policy.Generation,
		})
		if isPermanentError(cause) {
			logger.Error("permanent authorization reconciliation failure recorded; awaiting explicit reconciliation")
		} else {
			logger.Warn("transient authorization reconciliation failure recorded; awaiting explicit reconciliation")
		}
		return nil
	}
	return cause
}

func (e *AuthzServiceAccountSyncEvent) acquire(ctx context.Context) error {
	select {
	case e.concurrency <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("wait for authorization reconciliation capacity: %w", ctx.Err())
	}
}

func (e *AuthzServiceAccountSyncEvent) release() {
	<-e.concurrency
}

func (e *AuthzServiceAccountSyncEvent) desiredTuples(
	ctx context.Context,
	sa *models.ServiceAccount,
	grants []repository.AuthorizationGrant,
) ([]*models.ServiceAccountAppliedTuple, error) {
	if sa.State == int32(commonv1.STATE_DELETED) {
		return nil, nil
	}
	namespaces, err := e.serviceNamespaceRepo.ListAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("load registered permission namespaces: %w", err)
	}
	basePartition, err := e.partitionRepo.GetByID(ctx, sa.PartitionID)
	if err != nil {
		return nil, fmt.Errorf("load service account partition %s: %w", sa.PartitionID, err)
	}

	tree, err := e.partitionTree(ctx, basePartition)
	if err != nil {
		return nil, err
	}
	partitionsByID := make(map[string]*models.Partition, len(tree))
	partitionsByID[basePartition.ID] = basePartition

	desiredRelations := make([]security.RelationTuple, 0)
	for _, grant := range grants {
		resolved, resolveErr := authz.ResolveServiceGrants(
			map[string][]string{grant.Namespace: grant.Permissions},
			namespaces,
		)
		if resolveErr != nil {
			return nil, fmt.Errorf("invalid authorization policy grant: %w", resolveErr)
		}

		targets := []*models.Partition{basePartition}
		switch grant.Scope {
		case models.AuthorizationScopePartitionOnly:
		case models.AuthorizationScopePartitionTree:
			targets = tree
		default:
			return nil, fmt.Errorf("unsupported authorization scope %q", grant.Scope)
		}

		for _, partition := range targets {
			partitionsByID[partition.ID] = partition
			tenancyPath := fmt.Sprintf("%s/%s", partition.TenantID, partition.ID)
			desiredRelations = append(desiredRelations, authz.BuildServicePermissionTuples(
				tenancyPath,
				sa.ProfileID,
				grant.Namespace,
				resolved[grant.Namespace],
			)...)
		}
	}

	for _, partition := range partitionsByID {
		tenancyPath := fmt.Sprintf("%s/%s", partition.TenantID, partition.ID)
		desiredRelations = append(desiredRelations, authz.BuildServiceAccessTuple(tenancyPath, sa.ProfileID))
	}
	authz.SortRelationTuples(desiredRelations)

	desired := make([]*models.ServiceAccountAppliedTuple, 0, len(desiredRelations))
	for _, relation := range desiredRelations {
		desired = append(desired, appliedTupleModel(sa, relation))
	}
	return desired, nil
}

func (e *AuthzServiceAccountSyncEvent) partitionTree(
	ctx context.Context,
	root *models.Partition,
) ([]*models.Partition, error) {
	return buildPartitionTree(ctx, root, e.partitionRepo.GetChildren)
}

func buildPartitionTree(
	ctx context.Context,
	root *models.Partition,
	getChildren func(context.Context, string) ([]*models.Partition, error),
) ([]*models.Partition, error) {
	result := []*models.Partition{root}
	queue := []*models.Partition{root}
	seen := map[string]struct{}{root.ID: {}}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		children, err := getChildren(ctx, current.ID)
		if err != nil {
			return nil, fmt.Errorf("load children for partition %s: %w", current.ID, err)
		}
		for _, child := range children {
			if _, exists := seen[child.ID]; exists {
				continue
			}
			seen[child.ID] = struct{}{}
			result = append(result, child)
			queue = append(queue, child)
		}
	}
	slices.SortFunc(result, func(left, right *models.Partition) int {
		return compareTupleKey(left.ID, right.ID)
	})
	return result, nil
}

func appliedTupleModel(
	sa *models.ServiceAccount,
	tuple security.RelationTuple,
) *models.ServiceAccountAppliedTuple {
	return &models.ServiceAccountAppliedTuple{
		Namespace:        tuple.Object.Namespace,
		Object:           tuple.Object.ID,
		Relation:         tuple.Relation,
		SubjectNamespace: tuple.Subject.Namespace,
		SubjectObject:    tuple.Subject.ID,
		SubjectRelation:  tuple.Subject.Relation,
		BaseModel: data.BaseModel{
			TenantID:    sa.TenantID,
			PartitionID: sa.PartitionID,
		},
	}
}

func diffAuthorizationTuples(
	applied []*models.ServiceAccountAppliedTuple,
	desired []*models.ServiceAccountAppliedTuple,
) ([]security.RelationTuple, []security.RelationTuple) {
	appliedByKey := make(map[string]*models.ServiceAccountAppliedTuple, len(applied))
	desiredByKey := make(map[string]*models.ServiceAccountAppliedTuple, len(desired))
	for _, tuple := range applied {
		appliedByKey[appliedTupleKey(tuple)] = tuple
	}
	for _, tuple := range desired {
		desiredByKey[appliedTupleKey(tuple)] = tuple
	}

	deletes := make([]security.RelationTuple, 0)
	for key, tuple := range appliedByKey {
		if _, exists := desiredByKey[key]; !exists {
			deletes = append(deletes, relationTuple(tuple))
		}
	}
	writes := make([]security.RelationTuple, 0)
	for key, tuple := range desiredByKey {
		if _, exists := appliedByKey[key]; !exists {
			writes = append(writes, relationTuple(tuple))
		}
	}
	authz.SortRelationTuples(deletes)
	authz.SortRelationTuples(writes)
	return deletes, writes
}

func relationTuple(tuple *models.ServiceAccountAppliedTuple) security.RelationTuple {
	return security.RelationTuple{
		Object:   security.ObjectRef{Namespace: tuple.Namespace, ID: tuple.Object},
		Relation: tuple.Relation,
		Subject: security.SubjectRef{
			Namespace: tuple.SubjectNamespace,
			ID:        tuple.SubjectObject,
			Relation:  tuple.SubjectRelation,
		},
	}
}

func appliedTupleKey(tuple *models.ServiceAccountAppliedTuple) string {
	return tuple.Namespace + "\x00" + tuple.Object + "\x00" + tuple.Relation + "\x00" +
		tuple.SubjectNamespace + "\x00" + tuple.SubjectObject + "\x00" + tuple.SubjectRelation
}

func compareTupleKey(left, right string) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}
