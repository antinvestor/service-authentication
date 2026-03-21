package main

import (
	"context"
	"fmt"
	"testing"

	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	profilev1 "buf.build/gen/go/antinvestor/profile/protocolbuffers/go/profile/v1"
	"connectrpc.com/connect"
	aconfig "github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/pkg/botdefs"
	"github.com/stretchr/testify/require"
)

func TestBotEmail(t *testing.T) {
	t.Parallel()

	require.Equal(t, "notification.bot@stawi.org", botdefs.Email("notification"))
	require.Equal(t, "profile.bot@stawi.org", botdefs.Email("profile"))
	require.Equal(t, "payment-jenga.bot@stawi.org", botdefs.Email("payment-jenga"))
}

func TestBotServiceAccountName(t *testing.T) {
	t.Parallel()

	require.Equal(t, "notification", botServiceAccountName("notification"))
	require.Equal(t, "payment_jenga", botServiceAccountName("payment-jenga"))
	require.Equal(t, "notification_africastalking", botServiceAccountName("notification-africastalking"))
}

func TestDefaultBotDefinitionsAreValid(t *testing.T) {
	t.Parallel()

	bots := botdefs.All()
	require.NotEmpty(t, bots)

	seen := make(map[string]bool)
	for _, bot := range bots {
		require.NotEmpty(t, bot.Function, "bot function must not be empty")
		require.NotEmpty(t, bot.Description, "bot description must not be empty")
		require.NotEmpty(t, bot.Audiences, "bot %s must have at least one audience", bot.Function)
		require.False(t, seen[bot.Function], "duplicate bot function: %s", bot.Function)
		seen[bot.Function] = true
	}
}

// --- Fakes ---

type fakeBotProfileService struct {
	profiles map[string]*profilev1.ProfileObject
	failOn   map[string]error
}

func newFakeBotProfileService() *fakeBotProfileService {
	return &fakeBotProfileService{
		profiles: make(map[string]*profilev1.ProfileObject),
		failOn:   make(map[string]error),
	}
}

func (f *fakeBotProfileService) GetByContact(_ context.Context, contact string) (*profilev1.ProfileObject, error) {
	if p, ok := f.profiles[contact]; ok {
		return p, nil
	}
	return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("not found: %s", contact))
}

func (f *fakeBotProfileService) CreateBotProfile(_ context.Context, email string) (*profilev1.ProfileObject, error) {
	if err, ok := f.failOn[email]; ok {
		return nil, err
	}
	p := &profilev1.ProfileObject{}
	p.SetId("bot-profile-" + email)
	p.SetType(profilev1.ProfileType_BOT)
	f.profiles[email] = p
	return p, nil
}

type fakeBotPartitionService struct {
	serviceAccounts map[string]*partitionv1.ServiceAccountObject
	created         map[string]bool
	failOn          map[string]error
}

func newFakeBotPartitionService() *fakeBotPartitionService {
	return &fakeBotPartitionService{
		serviceAccounts: make(map[string]*partitionv1.ServiceAccountObject),
		created:         make(map[string]bool),
		failOn:          make(map[string]error),
	}
}

func (f *fakeBotPartitionService) ListServiceAccounts(_ context.Context, _ string) ([]*partitionv1.ServiceAccountObject, error) {
	accounts := make([]*partitionv1.ServiceAccountObject, 0, len(f.serviceAccounts))
	for _, sa := range f.serviceAccounts {
		accounts = append(accounts, sa)
	}
	return accounts, nil
}

func (f *fakeBotPartitionService) CreateServiceAccount(
	_ context.Context,
	_, profileID, name, saType string,
	audiences []string,
) (*partitionv1.CreateServiceAccountResponse, error) {
	if err, ok := f.failOn[profileID]; ok {
		return nil, err
	}
	sa := &partitionv1.ServiceAccountObject{}
	sa.SetId("sa-" + profileID)
	sa.SetProfileId(profileID)
	sa.SetType(saType)
	sa.SetAudiences(audiences)
	f.serviceAccounts[profileID] = sa
	f.created[name] = true

	resp := &partitionv1.CreateServiceAccountResponse{}
	resp.SetData(sa)
	resp.SetClientSecret("test-secret-" + profileID)
	return resp, nil
}

// --- Tests ---

func TestSeedBotUsersCreatesAllProfilesAndServiceAccounts(t *testing.T) {
	t.Parallel()

	fakeProfiles := newFakeBotProfileService()
	fakePartitions := newFakeBotPartitionService()
	seeder := &botUserSeeder{
		profiles:   fakeProfiles,
		partitions: fakePartitions,
	}

	result, err := seeder.SeedBotUsers(context.Background(), rootPartitionProductionID)
	require.NoError(t, err)

	bots := botdefs.All()
	require.Equal(t, len(bots), result.Created)
	require.Equal(t, 0, result.Existing)
	require.Equal(t, 0, result.Errors)
	require.Len(t, result.Details, len(bots))

	for _, detail := range result.Details {
		require.True(t, detail.CreatedProfile, "expected profile created for %s", detail.Function)
		require.True(t, detail.CreatedSA, "expected SA created for %s", detail.Function)
		require.NotEmpty(t, detail.ProfileID, "expected profile ID for %s", detail.Function)
		require.NotEmpty(t, detail.ServiceAccountID, "expected SA ID for %s", detail.Function)
		require.Empty(t, detail.Error)
	}

	for _, bot := range bots {
		expectedName := botServiceAccountName(bot.Function)
		require.True(t, fakePartitions.created[expectedName], "SA not created for %s", expectedName)
	}
}

func TestSeedBotUsersSkipsExistingProfileAndSA(t *testing.T) {
	t.Parallel()

	fakeProfiles := newFakeBotProfileService()
	fakePartitions := newFakeBotPartitionService()

	existingEmail := botdefs.Email("notification")
	existingProfile := &profilev1.ProfileObject{}
	existingProfile.SetId("existing-profile-id")
	existingProfile.SetType(profilev1.ProfileType_BOT)
	fakeProfiles.profiles[existingEmail] = existingProfile

	existingSA := &partitionv1.ServiceAccountObject{}
	existingSA.SetId("existing-sa-id")
	existingSA.SetProfileId("existing-profile-id")
	fakePartitions.serviceAccounts["existing-profile-id"] = existingSA

	seeder := &botUserSeeder{
		profiles:   fakeProfiles,
		partitions: fakePartitions,
	}

	result, err := seeder.SeedBotUsers(context.Background(), rootPartitionProductionID)
	require.NoError(t, err)

	require.Equal(t, 1, result.Existing)
	require.Equal(t, len(botdefs.All())-1, result.Created)
	require.Equal(t, 0, result.Errors)

	for _, detail := range result.Details {
		if detail.Function == "notification" {
			require.False(t, detail.CreatedProfile)
			require.False(t, detail.CreatedSA)
			require.Equal(t, "existing-profile-id", detail.ProfileID)
			require.Equal(t, "existing-sa-id", detail.ServiceAccountID)
		}
	}
}

func TestSeedBotUsersCreatesOnlySAWhenProfileExists(t *testing.T) {
	t.Parallel()

	fakeProfiles := newFakeBotProfileService()
	fakePartitions := newFakeBotPartitionService()

	existingEmail := botdefs.Email("payment")
	existingProfile := &profilev1.ProfileObject{}
	existingProfile.SetId("existing-payment-profile")
	existingProfile.SetType(profilev1.ProfileType_BOT)
	fakeProfiles.profiles[existingEmail] = existingProfile

	seeder := &botUserSeeder{
		profiles:   fakeProfiles,
		partitions: fakePartitions,
	}

	result, err := seeder.SeedBotUsers(context.Background(), rootPartitionProductionID)
	require.NoError(t, err)

	for _, detail := range result.Details {
		if detail.Function == "payment" {
			require.False(t, detail.CreatedProfile)
			require.True(t, detail.CreatedSA)
			require.Equal(t, "existing-payment-profile", detail.ProfileID)
			require.NotEmpty(t, detail.ServiceAccountID)
		}
	}
}

func TestSeedBotUsersHandlesProfileCreateError(t *testing.T) {
	t.Parallel()

	fakeProfiles := newFakeBotProfileService()
	fakePartitions := newFakeBotPartitionService()
	failEmail := botdefs.Email("payment")
	fakeProfiles.failOn[failEmail] = fmt.Errorf("service unavailable")

	seeder := &botUserSeeder{
		profiles:   fakeProfiles,
		partitions: fakePartitions,
	}

	result, err := seeder.SeedBotUsers(context.Background(), rootPartitionProductionID)
	require.NoError(t, err)

	require.Equal(t, 1, result.Errors)

	for _, detail := range result.Details {
		if detail.Function == "payment" {
			require.Contains(t, detail.Error, "profile")
			require.Contains(t, detail.Error, "create failed")
			require.Empty(t, detail.ServiceAccountID)
		}
	}
}

func TestSeedBotUsersHandlesSACreateError(t *testing.T) {
	t.Parallel()

	fakeProfiles := newFakeBotProfileService()
	fakePartitions := newFakeBotPartitionService()

	ledgerProfileID := "bot-profile-" + botdefs.Email("ledger")
	fakePartitions.failOn[ledgerProfileID] = fmt.Errorf("permission denied")

	seeder := &botUserSeeder{
		profiles:   fakeProfiles,
		partitions: fakePartitions,
	}

	result, err := seeder.SeedBotUsers(context.Background(), rootPartitionProductionID)
	require.NoError(t, err)

	require.Equal(t, 1, result.Errors)

	for _, detail := range result.Details {
		if detail.Function == "ledger" {
			require.Contains(t, detail.Error, "service account")
			require.Contains(t, detail.Error, "create failed")
			require.NotEmpty(t, detail.ProfileID, "profile should still be created")
		}
	}
}

func TestSeedBotUsersCommandRejectsInvalidArgs(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		args        []string
		errContains string
	}{
		{
			name:        "missing_environment",
			args:        []string{},
			errContains: "requires --environment",
		},
		{
			name:        "unsupported_environment",
			args:        []string{"--environment", "development"},
			errContains: "unsupported environment",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := runSeedBotUsersCommand(context.Background(), aconfig.AuthenticationConfig{}, tc.args)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.errContains)
		})
	}
}
