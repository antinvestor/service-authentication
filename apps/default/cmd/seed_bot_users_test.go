package main

import (
	"context"
	"fmt"
	"testing"

	profilev1 "buf.build/gen/go/antinvestor/profile/protocolbuffers/go/profile/v1"
	"connectrpc.com/connect"
	aconfig "github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/stretchr/testify/require"
)

func TestBotEmail(t *testing.T) {
	t.Parallel()

	require.Equal(t, "notification.bot@stawi.org", botEmail("notification"))
	require.Equal(t, "profile.bot@stawi.org", botEmail("profile"))
	require.Equal(t, "payment-jenga.bot@stawi.org", botEmail("payment-jenga"))
}

func TestDefaultBotDefinitionsNotEmpty(t *testing.T) {
	t.Parallel()

	bots := defaultBotDefinitions()
	require.NotEmpty(t, bots)

	seen := make(map[string]bool)
	for _, bot := range bots {
		require.NotEmpty(t, bot.Function, "bot function must not be empty")
		require.NotEmpty(t, bot.Description, "bot description must not be empty")
		require.False(t, seen[bot.Function], "duplicate bot function: %s", bot.Function)
		seen[bot.Function] = true
	}
}

type fakeBotProfileService struct {
	profiles map[string]*profilev1.ProfileObject
	created  map[string]bool
	failOn   map[string]error
}

func newFakeBotProfileService() *fakeBotProfileService {
	return &fakeBotProfileService{
		profiles: make(map[string]*profilev1.ProfileObject),
		created:  make(map[string]bool),
		failOn:   make(map[string]error),
	}
}

func (f *fakeBotProfileService) GetByContact(_ context.Context, contact string) (*profilev1.ProfileObject, error) {
	if p, ok := f.profiles[contact]; ok {
		return p, nil
	}
	return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("not found: %s", contact))
}

func (f *fakeBotProfileService) CreateBotProfile(_ context.Context, email, _ string) (*profilev1.ProfileObject, error) {
	if err, ok := f.failOn[email]; ok {
		return nil, err
	}
	p := &profilev1.ProfileObject{}
	p.SetId("bot-profile-" + email)
	p.SetType(profilev1.ProfileType_BOT)
	f.profiles[email] = p
	f.created[email] = true
	return p, nil
}

func TestSeedBotUsersCreatesAllProfiles(t *testing.T) {
	t.Parallel()

	fake := newFakeBotProfileService()
	seeder := &botUserSeeder{profiles: fake}

	result := seeder.SeedBotUsers(context.Background())

	bots := defaultBotDefinitions()
	require.Equal(t, len(bots), result.Created)
	require.Equal(t, 0, result.Existing)
	require.Equal(t, 0, result.Errors)
	require.Len(t, result.Details, len(bots))

	for _, detail := range result.Details {
		require.True(t, detail.Created, "expected %s to be created", detail.Function)
		require.NotEmpty(t, detail.ProfileID, "expected profile ID for %s", detail.Function)
		require.Empty(t, detail.Error)
	}
}

func TestSeedBotUsersSkipsExisting(t *testing.T) {
	t.Parallel()

	fake := newFakeBotProfileService()

	existingEmail := botEmail("notification")
	existingProfile := &profilev1.ProfileObject{}
	existingProfile.SetId("existing-profile-id")
	existingProfile.SetType(profilev1.ProfileType_BOT)
	fake.profiles[existingEmail] = existingProfile

	seeder := &botUserSeeder{profiles: fake}

	result := seeder.SeedBotUsers(context.Background())

	require.Equal(t, 1, result.Existing)
	require.Equal(t, len(defaultBotDefinitions())-1, result.Created)
	require.Equal(t, 0, result.Errors)

	for _, detail := range result.Details {
		if detail.Function == "notification" {
			require.False(t, detail.Created)
			require.Equal(t, "existing-profile-id", detail.ProfileID)
		}
	}
}

func TestSeedBotUsersHandlesCreateError(t *testing.T) {
	t.Parallel()

	fake := newFakeBotProfileService()
	failEmail := botEmail("payment")
	fake.failOn[failEmail] = fmt.Errorf("service unavailable")

	seeder := &botUserSeeder{profiles: fake}

	result := seeder.SeedBotUsers(context.Background())

	require.Equal(t, 1, result.Errors)
	require.Equal(t, len(defaultBotDefinitions())-1, result.Created)

	for _, detail := range result.Details {
		if detail.Function == "payment" {
			require.Contains(t, detail.Error, "create failed")
			require.Empty(t, detail.ProfileID)
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
