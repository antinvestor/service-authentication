package botdefs

import "fmt"

const (
	EmailDomain        = "stawi.org"
	ServiceAccountType = "internal"
)

// Definition describes a platform service bot and its service account configuration.
type Definition struct {
	// Function is the service function name used to derive the email address
	// (e.g. "notification" → notification.bot@stawi.org).
	Function string
	// Description is a human-readable label for the bot profile.
	Description string
	// Audiences lists the namespace permissions this service account needs.
	Audiences []string
}

// Email returns the bot email address for the given function.
func Email(function string) string {
	return fmt.Sprintf("%s.bot@%s", function, EmailDomain)
}

// All returns the canonical list of platform service bot definitions.
// Each entry maps 1:1 to a service account that should exist on the root partition.
func All() []Definition {
	return []Definition{
		{
			Function:    "authentication",
			Description: "Authentication service bot",
			Audiences:   []string{"service_profile", "service_tenancy", "service_device"},
		},
		{
			Function:    "profile",
			Description: "Profile service bot",
			Audiences:   []string{"service_notifications", "service_tenancy", "service_device"},
		},
		{
			Function:    "tenancy",
			Description: "Tenancy service bot",
			Audiences:   []string{"service_notifications", "service_profile"},
		},
		{
			Function:    "notification",
			Description: "Notification service bot",
			Audiences:   []string{"service_profile", "service_tenancy"},
		},
		{
			Function:    "device",
			Description: "Device service bot",
			Audiences:   []string{"service_notifications", "service_profile", "service_device"},
		},
		{
			Function:    "settings",
			Description: "Settings service bot",
			Audiences:   []string{"service_notifications", "service_profile", "service_device"},
		},
		{
			Function:    "payment",
			Description: "Payment service bot",
			Audiences:   []string{"service_profile", "service_tenancy"},
		},
		{
			Function:    "payment-jenga",
			Description: "Jenga payment integration bot",
			Audiences:   []string{"service_profile", "service_tenancy"},
		},
		{
			Function:    "ledger",
			Description: "Ledger service bot",
			Audiences:   []string{"service_tenancy"},
		},
		{
			Function:    "billing",
			Description: "Billing service bot",
			Audiences:   []string{"service_tenancy"},
		},
		{
			Function:    "files",
			Description: "Files service bot",
			Audiences:   []string{"service_profile", "service_tenancy"},
		},
		{
			Function:    "chat-drone",
			Description: "Chat drone service bot",
			Audiences:   []string{"service_notifications", "service_profile", "service_device"},
		},
		{
			Function:    "chat-gateway",
			Description: "Chat gateway service bot",
			Audiences:   []string{"service_notifications", "service_chat_drone", "service_device"},
		},
		{
			Function:    "foundry",
			Description: "Foundry service bot",
			Audiences:   []string{"service_profile", "service_tenancy"},
		},
		{
			Function:    "gitvault",
			Description: "Gitvault service bot",
			Audiences:   []string{"service_profile", "service_tenancy"},
		},
		{
			Function:    "trustage",
			Description: "Trustage service bot",
			Audiences:   []string{"service_profile", "service_tenancy"},
		},
		{
			Function:    "notification-africastalking",
			Description: "Africa's Talking notification integration bot",
			Audiences:   []string{"service_profile", "service_tenancy", "service_notifications", "service_settings"},
		},
		{
			Function:    "notification-emailsmtp",
			Description: "SMTP email notification integration bot",
			Audiences:   []string{"service_profile", "service_tenancy", "service_notifications", "service_settings"},
		},
		{
			Function:    "sync",
			Description: "Partition synchronisation bot",
			Audiences:   []string{"service_tenancy"},
		},
	}
}

// EmailToFunction builds a reverse lookup map from email → function name.
func EmailToFunction() map[string]string {
	m := make(map[string]string)
	for _, d := range All() {
		m[Email(d.Function)] = d.Function
	}
	return m
}

// ProfileIDToDefinition builds a lookup from a profile_id placeholder (the
// underscore-separated function name used in migration SQL) to Definition.
// This allows matching seeded SA records whose profile_id is still a
// placeholder like "service_authentication" or "service_notifications".
func ProfileIDPlaceholders() map[string]Definition {
	m := make(map[string]Definition)
	for _, d := range All() {
		// The migrations use profile_id values like "service_authentication",
		// "service_notifications", "foundry", etc.
		// These are NOT valid profile service IDs (those are xid-style strings).
		m[Email(d.Function)] = d
	}
	return m
}
