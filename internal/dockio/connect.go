package dockio

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
)

// App connect (SOIDC v1 §14): an operator clicks one button, approves in døckio,
// and comes back with an OIDC client created and filled in. The guide this
// implements is docs/dockio.md; the steps that need storage live in
// internal/identity, and this file holds only the wire.

// Manifest is what døckio fetches from the application while an operator
// approves a connection. It is how døckio learns the application's URIs.
type Manifest struct {
	Version                string   `json:"dockio_manifest"`
	Name                   string   `json:"name"`
	LogoURI                string   `json:"logo_uri,omitempty"`
	AppKey                 string   `json:"app_key"`
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`
	BackchannelLogoutURI   string   `json:"backchannel_logout_uri,omitempty"`
	RevocationURI          string   `json:"revocation_uri,omitempty"`
	Needs                  []string `json:"needs,omitempty"`
	HomeRealm              string   `json:"home_realm"`
	MaxExpiryDays          int      `json:"max_expiry_days,omitempty"`
}

// ConnectRequest is what the browser carries to døckio's connect page.
type ConnectRequest struct {
	ManifestURI   string
	ReturnURI     string
	State         string
	CodeChallenge string
	// ConnectionID renews an existing connection instead of making a new one.
	ConnectionID string
}

// ConnectURL builds the address the browser is sent to.
func ConnectURL(d Discovery, r ConnectRequest) string {
	q := url.Values{
		"manifest_uri":          {r.ManifestURI},
		"return_uri":            {r.ReturnURI},
		"state":                 {r.State},
		"code_challenge":        {r.CodeChallenge},
		"code_challenge_method": {"S256"},
	}
	if r.ConnectionID != "" {
		q.Set("connection", r.ConnectionID)
	}
	return d.ConnectEndpoint + "?" + q.Encode()
}

// Grant is døckio's answer to a connect code: the credentials of the OIDC client
// it created (or renewed), and where they live.
type Grant struct {
	ConnectionID          string `json:"connection_id"`
	Issuer                string `json:"issuer"` // the TENANT issuer
	ClientID              string `json:"client_id"`
	ClientSecret          string `json:"client_secret"`
	ClientSecretExpiresAt *int64 `json:"client_secret_expires_at"` // may be null
	Tenant                struct {
		Name    string `json:"name"`
		Address string `json:"address"`
	} `json:"tenant"`
	Realm     string          `json:"realm"`   // may be {home_realm}-{tenant}; store what comes back
	AppKey    *string         `json:"app_key"` // may be null
	Switches  map[string]bool `json:"switches"`
	ManageURI string          `json:"manage_uri"`
}

// ErrInvalidGrant is døckio refusing a connect code: expired, already used, or
// not issued for this verifier and return URI. Show it as "the link expired".
var ErrInvalidGrant = errors.New("dockio: the connect code was refused")

// ExchangeConnectCode trades the one-time code for the credentials. It is a
// server-to-server call: the secret in the answer never touches a browser.
//
// A code's first use spends it, whether that use succeeds or fails.
func ExchangeConnectCode(ctx context.Context, hc *http.Client, d Discovery, code, verifier, returnURI string) (Grant, error) {
	if !d.SupportsConnect() {
		return Grant{}, ErrConnectNotSupported
	}
	var g Grant
	_, err := sendJSON(ctx, hc, http.MethodPost, d.ConnectTokenEndpoint, "",
		map[string]string{"code": code, "code_verifier": verifier, "return_uri": returnURI}, &g)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusBadRequest {
			return Grant{}, ErrInvalidGrant
		}
		return Grant{}, err
	}
	return g, nil
}

// ---------------------------------------------------------------- PKCE & randomness

// PKCE is a verifier and its S256 challenge.
type PKCE struct {
	Verifier  string
	Challenge string
}

// NewPKCE makes a fresh pair.
func NewPKCE() (PKCE, error) {
	v, err := RandomToken(32)
	if err != nil {
		return PKCE{}, err
	}
	return PKCE{Verifier: v, Challenge: Challenge(v)}, nil
}

// Challenge is the S256 code challenge of verifier.
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// RandomToken returns n random bytes, base64url-encoded: printable, URL-safe and
// well inside the 16-512 characters døckio accepts for a state.
func RandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
