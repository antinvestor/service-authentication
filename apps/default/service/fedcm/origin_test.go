package fedcm_test

import (
	"testing"

	"github.com/antinvestor/service-authentication/apps/default/service/fedcm"
	"github.com/stretchr/testify/require"
)

func TestOriginMatchesRedirectURIs_ExactMatch(t *testing.T) {
	ok, err := fedcm.OriginMatchesRedirectURIs("https://app.example.com", []string{
		"https://app.example.com/cb",
	})
	require.NoError(t, err)
	require.True(t, ok)
}

func TestOriginMatchesRedirectURIs_MultipleURIsOneMatches(t *testing.T) {
	ok, err := fedcm.OriginMatchesRedirectURIs("https://b.example.com", []string{
		"https://a.example.com/cb",
		"https://b.example.com/cb",
	})
	require.NoError(t, err)
	require.True(t, ok)
}

func TestOriginMatchesRedirectURIs_NoMatchReturnsFalse(t *testing.T) {
	ok, err := fedcm.OriginMatchesRedirectURIs("https://evil.example.com", []string{
		"https://app.example.com/cb",
	})
	require.NoError(t, err)
	require.False(t, ok)
}

func TestOriginMatchesRedirectURIs_PortMismatchDoesNotMatch(t *testing.T) {
	ok, err := fedcm.OriginMatchesRedirectURIs("https://app.example.com:8443", []string{
		"https://app.example.com/cb",
	})
	require.NoError(t, err)
	require.False(t, ok)
}

func TestOriginMatchesRedirectURIs_SchemeMismatchDoesNotMatch(t *testing.T) {
	ok, err := fedcm.OriginMatchesRedirectURIs("http://app.example.com", []string{
		"https://app.example.com/cb",
	})
	require.NoError(t, err)
	require.False(t, ok)
}

func TestOriginMatchesRedirectURIs_EmptyOriginErrors(t *testing.T) {
	_, err := fedcm.OriginMatchesRedirectURIs("", []string{"https://a/b"})
	require.Error(t, err)
}

func TestOriginMatchesRedirectURIs_MalformedRedirectURISkipped(t *testing.T) {
	ok, err := fedcm.OriginMatchesRedirectURIs("https://app.example.com", []string{
		"::::not-a-url",
		"https://app.example.com/cb",
	})
	require.NoError(t, err)
	require.True(t, ok)
}
