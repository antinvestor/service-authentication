package fedcm_test

import (
	"testing"

	"github.com/antinvestor/service-authentication/apps/default/service/fedcm"
	"github.com/stretchr/testify/require"
)

func TestResolveBranding_UsesPartitionPropertiesFirst(t *testing.T) {
	defaults := fedcm.BrandingDefaults{
		PrivacyPolicyURL:  "https://default/privacy",
		TermsOfServiceURL: "https://default/tos",
		IconURL:           "https://default/icon.png",
		BackgroundColor:   "#000000",
	}
	partition := map[string]string{
		"privacy_policy_url":         "https://tenant-a/privacy",
		"terms_of_service_url":       "https://tenant-a/tos",
		"branding_icon_url":          "https://tenant-a/icon.png",
		"branding_background_colour": "#ff0000",
	}

	out := fedcm.ResolveBranding(partition, nil, defaults)

	require.Equal(t, "https://tenant-a/privacy", out.PrivacyPolicyURL)
	require.Equal(t, "https://tenant-a/tos", out.TermsOfServiceURL)
	require.Equal(t, "https://tenant-a/icon.png", out.IconURL)
	require.Equal(t, "#ff0000", out.BackgroundColor)
}

func TestResolveBranding_FallsThroughToTenant(t *testing.T) {
	defaults := fedcm.BrandingDefaults{PrivacyPolicyURL: "https://default/privacy"}
	tenant := map[string]string{"privacy_policy_url": "https://tenant/privacy"}

	out := fedcm.ResolveBranding(nil, tenant, defaults)

	require.Equal(t, "https://tenant/privacy", out.PrivacyPolicyURL)
}

func TestResolveBranding_FallsThroughToDefaults(t *testing.T) {
	defaults := fedcm.BrandingDefaults{PrivacyPolicyURL: "https://default/privacy"}

	out := fedcm.ResolveBranding(nil, nil, defaults)

	require.Equal(t, "https://default/privacy", out.PrivacyPolicyURL)
}

func TestResolveBranding_EmptyPartitionValueFallsThrough(t *testing.T) {
	defaults := fedcm.BrandingDefaults{PrivacyPolicyURL: "https://default/privacy"}
	partition := map[string]string{"privacy_policy_url": ""}

	out := fedcm.ResolveBranding(partition, nil, defaults)

	require.Equal(t, "https://default/privacy", out.PrivacyPolicyURL)
}
