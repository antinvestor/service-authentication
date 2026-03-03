package business

import (
	"context"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/data"
	fevents "github.com/pitabwire/frame/events"
	"github.com/pitabwire/util"
)

// ReQueueServiceAccountsForSync emits authz sync events for all service accounts
// in the given partition (or all if partitionID is empty). This re-writes all
// Keto tuples for service accounts, ensuring they match the database state.
func ReQueueServiceAccountsForSync(
	ctx context.Context,
	serviceAccountRepo repository.ServiceAccountRepository,
	eventsMan fevents.Manager,
	query *data.SearchQuery,
) error {
	return reQueueServiceAccounts(ctx, serviceAccountRepo, eventsMan, query, events.EventKeyAuthzServiceAccountSync)
}

// ReQueueServiceAccountsForHydraSync emits SA synchronisation events for all
// service accounts, ensuring each SA's Hydra OAuth2 client matches the database state.
func ReQueueServiceAccountsForHydraSync(
	ctx context.Context,
	serviceAccountRepo repository.ServiceAccountRepository,
	eventsMan fevents.Manager,
	query *data.SearchQuery,
) error {
	return reQueueServiceAccounts(ctx, serviceAccountRepo, eventsMan, query, events.EventKeyServiceAccountSynchronization)
}

func reQueueServiceAccounts(
	ctx context.Context,
	serviceAccountRepo repository.ServiceAccountRepository,
	eventsMan fevents.Manager,
	query *data.SearchQuery,
	eventKey string,
) error {
	jobResult, err := serviceAccountRepo.Search(ctx, query)
	if err != nil {
		return err
	}

	for {
		result, ok := jobResult.ReadResult(ctx)
		if !ok {
			return nil
		}

		if result.IsError() {
			return result.Error()
		}

		for _, sa := range result.Item() {
			if emitErr := eventsMan.Emit(ctx, eventKey, data.JSONMap{"id": sa.GetID()}); emitErr != nil {
				util.Log(ctx).WithError(emitErr).
					WithField("service_account_id", sa.GetID()).
					WithField("event", eventKey).
					Warn("failed to emit service account sync event")
			}
		}
	}
}
