package fedcm_test

import (
	"net/url"
	"testing"

	"github.com/antinvestor/service-authentication/apps/default/service/fedcm"
	"github.com/stretchr/testify/require"
)

func TestBuildAuthorizeURL_IncludesAllRequiredParams(t *testing.T) {
	u, err := fedcm.BuildAuthorizeURL(fedcm.AuthorizeURLInput{
		HydraPublicURL: "https://hydra.example.com",
		ClientID:       "client_A",
		RedirectURI:    "https://auth.example.com/_internal/fedcm-callback",
		Scopes:         []string{"openid", "profile", "email"},
		Nonce:          "nonce_123",
		State:          "state_abc",
		CodeChallenge:  "cc_xyz",
	})
	require.NoError(t, err)

	parsed, perr := url.Parse(u)
	require.NoError(t, perr)
	q := parsed.Query()
	require.Equal(t, "code", q.Get("response_type"))
	require.Equal(t, "client_A", q.Get("client_id"))
	require.Equal(t, "https://auth.example.com/_internal/fedcm-callback", q.Get("redirect_uri"))
	require.Equal(t, "openid profile email", q.Get("scope"))
	require.Equal(t, "nonce_123", q.Get("nonce"))
	require.Equal(t, "state_abc", q.Get("state"))
	require.Equal(t, "cc_xyz", q.Get("code_challenge"))
	require.Equal(t, "S256", q.Get("code_challenge_method"))
}

func TestGeneratePKCEPair_ProducesS256CompatibleValues(t *testing.T) {
	v, c, err := fedcm.GeneratePKCEPair()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(v), 43)
	require.LessOrEqual(t, len(v), 128)
	require.NotEmpty(t, c)
	require.NotEqual(t, v, c)
}

func TestExtractLoginChallenge_FromHydraRedirect(t *testing.T) {
	loc := "https://auth.example.com/s/login?login_challenge=chal_abc"
	chal, err := fedcm.ExtractLoginChallenge(loc)
	require.NoError(t, err)
	require.Equal(t, "chal_abc", chal)
}

func TestExtractConsentChallenge_FromHydraRedirect(t *testing.T) {
	loc := "https://auth.example.com/s/consent?consent_challenge=chal_def"
	chal, err := fedcm.ExtractConsentChallenge(loc)
	require.NoError(t, err)
	require.Equal(t, "chal_def", chal)
}

func TestExtractCallbackCode_FromHydraRedirect(t *testing.T) {
	loc := "https://auth.example.com/_internal/fedcm-callback?code=zzz&state=state_abc"
	code, state, err := fedcm.ExtractCallbackCode(loc)
	require.NoError(t, err)
	require.Equal(t, "zzz", code)
	require.Equal(t, "state_abc", state)
}
