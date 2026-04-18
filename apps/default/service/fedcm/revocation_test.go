package fedcm_test

import (
	"context"
	"testing"
	"time"

	"github.com/antinvestor/service-authentication/apps/default/service/fedcm"
	"github.com/stretchr/testify/require"
)

type fakeKV struct {
	m map[string]time.Time
}

func newFakeKV() *fakeKV { return &fakeKV{m: map[string]time.Time{}} }
func (f *fakeKV) Set(_ context.Context, key string, _ string, ttl time.Duration) error {
	f.m[key] = time.Now().Add(ttl)
	return nil
}
func (f *fakeKV) Get(_ context.Context, key string) (string, bool, error) {
	exp, ok := f.m[key]
	if !ok {
		return "", false, nil
	}
	if time.Now().After(exp) {
		delete(f.m, key)
		return "", false, nil
	}
	return "1", true, nil
}

func TestRevocation_RevokeThenIsRevoked(t *testing.T) {
	store := fedcm.NewRevocationStore(newFakeKV())
	ctx := context.Background()

	require.NoError(t, store.Revoke(ctx, "prof_1", "client_A"))

	revoked, err := store.IsRevoked(ctx, "prof_1", "client_A")
	require.NoError(t, err)
	require.True(t, revoked)
}

func TestRevocation_UnrelatedPairNotRevoked(t *testing.T) {
	store := fedcm.NewRevocationStore(newFakeKV())
	ctx := context.Background()
	require.NoError(t, store.Revoke(ctx, "prof_1", "client_A"))

	revoked, err := store.IsRevoked(ctx, "prof_2", "client_A")
	require.NoError(t, err)
	require.False(t, revoked)

	revoked, err = store.IsRevoked(ctx, "prof_1", "client_B")
	require.NoError(t, err)
	require.False(t, revoked)
}
