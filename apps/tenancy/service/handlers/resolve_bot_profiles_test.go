package handlers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMigrationProfileID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		function string
		expected string
	}{
		{"authentication", "service_authentication"},
		{"profile", "service_profile"},
		{"tenancy", "service_tenancy"},
		{"notification", "service_notifications"},
		{"device", "service_devices"},
		{"settings", "service_settings"},
		{"payment", "service_payment"},
		{"payment-jenga", "service_payment_jenga"},
		{"ledger", "service_ledger"},
		{"billing", "service_billing"},
		{"files", "service_files"},
		{"chat-drone", "service_chat_drone"},
		{"chat-gateway", "service_chat_gateway"},
		{"foundry", "foundry"},
		{"gitvault", "gitvault"},
		{"trustage", "trustage"},
		{"notification-africastalking", "service_notification_africastalking"},
		{"notification-emailsmtp", "service_notification_emailsmtp"},
		{"sync", "synchronise_partitions"},
	}

	for _, tt := range tests {
		t.Run(tt.function, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.expected, migrationProfileID(tt.function))
		})
	}
}

func TestIsPlaceholderProfileID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		profileID     string
		isPlaceholder bool
	}{
		{"", true},
		{"service_authentication", true},
		{"service_notifications", true},
		{"foundry", true},
		{"trustage", true},
		{"c2f4j7au6s7f91uqnolg", false},
		{"9bsv0s3pbdv002o80qhg", false},
	}

	for _, tt := range tests {
		t.Run(tt.profileID, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.isPlaceholder, isPlaceholderProfileID(tt.profileID))
		})
	}
}

func TestBuildPlaceholderEmailMap(t *testing.T) {
	t.Parallel()

	m := buildPlaceholderEmailMap()

	require.Equal(t, "authentication.bot@stawi.org", m["service_authentication"])
	require.Equal(t, "notification.bot@stawi.org", m["service_notifications"])
	require.Equal(t, "foundry.bot@stawi.org", m["foundry"])
	require.Equal(t, "sync.bot@stawi.org", m["synchronise_partitions"])
	require.Equal(t, "notification-africastalking.bot@stawi.org", m["service_notification_africastalking"])
}
