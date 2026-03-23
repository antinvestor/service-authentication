package handlers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBotEmailFromClientID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		clientID string
		expected string
	}{
		{"service-authentication", "authentication.bot@stawi.org"},
		{"service-profile", "profile.bot@stawi.org"},
		{"service-notification", "notification.bot@stawi.org"},
		{"service-devices", "devices.bot@stawi.org"},
		{"service-payment-jenga", "payment-jenga.bot@stawi.org"},
		{"service-notification-integration-africastalking", "notification-integration-africastalking.bot@stawi.org"},
		{"foundry", "foundry.bot@stawi.org"},
		{"gitvault", "gitvault.bot@stawi.org"},
		{"trustage", "trustage.bot@stawi.org"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.clientID, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.expected, botEmailFromClientID(tt.clientID))
		})
	}
}

func TestIsPlaceholderProfileID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		profileID     string
		isPlaceholder bool
	}{
		{"empty", "", true},
		{"service_authentication", "service_authentication", true},
		{"service_notification", "service_notification", true},
		{"foundry", "foundry", true},
		{"trustage", "trustage", true},
		{"valid_xid_1", "c2f4j7au6s7f91uqnolg", false},
		{"valid_xid_2", "9bsv0s3pbdv002o80qhg", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.isPlaceholder, isPlaceholderProfileID(tt.profileID))
		})
	}
}
