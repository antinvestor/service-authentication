// Copyright 2023-2026 Ant Investor Ltd
// Licensed under the Apache License, Version 2.0 (see LICENSE).

package fedcm

const (
	PropKeyPrivacyPolicyURL  = "privacy_policy_url"
	PropKeyTermsOfServiceURL = "terms_of_service_url"
	PropKeyIconURL           = "branding_icon_url"
	PropKeyBackgroundColor   = "branding_background_colour"
)

type BrandingDefaults struct {
	PrivacyPolicyURL  string
	TermsOfServiceURL string
	IconURL           string
	BackgroundColor   string
}

type Branding struct {
	PrivacyPolicyURL  string
	TermsOfServiceURL string
	IconURL           string
	BackgroundColor   string
}

// ResolveBranding chooses values in order: partition properties → tenant
// properties → defaults. Empty values in earlier layers fall through.
func ResolveBranding(partition, tenant map[string]string, defaults BrandingDefaults) Branding {
	pick := func(key, fallback string) string {
		if v, ok := partition[key]; ok && v != "" {
			return v
		}
		if v, ok := tenant[key]; ok && v != "" {
			return v
		}
		return fallback
	}
	return Branding{
		PrivacyPolicyURL:  pick(PropKeyPrivacyPolicyURL, defaults.PrivacyPolicyURL),
		TermsOfServiceURL: pick(PropKeyTermsOfServiceURL, defaults.TermsOfServiceURL),
		IconURL:           pick(PropKeyIconURL, defaults.IconURL),
		BackgroundColor:   pick(PropKeyBackgroundColor, defaults.BackgroundColor),
	}
}
