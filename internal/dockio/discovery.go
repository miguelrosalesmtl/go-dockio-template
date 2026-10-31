package dockio

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Discovery is the subset of a døckio OpenID configuration this application reads.
//
// The station (https://døck.io) and each tenant (https://døck.io/t/acme) publish
// one. The station's carries the app connect fields (SOIDC v1 §14); a tenant's
// is what sign-in and every call made with a client's credentials use.
type Discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`

	CatalogEndpoint              string `json:"dockio_catalog_endpoint"`
	EffectivePermissionsEndpoint string `json:"dockio_effective_permissions_endpoint"`

	ConnectEndpoint      string `json:"dockio_connect_endpoint"`
	ConnectTokenEndpoint string `json:"dockio_connect_token_endpoint"`
	ConnectionEndpoint   string `json:"dockio_connection_endpoint"`
	ConnectExpiryDays    []int  `json:"dockio_connect_expiry_days"`
}

// ErrConnectNotSupported means the station has no app connect endpoints: it is a
// døckio that predates §14. Quick connect must be hidden and manual setup shown.
var ErrConnectNotSupported = errors.New("dockio: this station cannot connect in one click")

// SupportsConnect reports whether Quick connect can be offered.
func (d Discovery) SupportsConnect() bool {
	return d.ConnectEndpoint != "" && d.ConnectTokenEndpoint != ""
}

// endpoints lists every endpoint the document names, for the origin check.
func (d Discovery) endpoints() map[string]string {
	return map[string]string{
		"authorization_endpoint":                d.AuthorizationEndpoint,
		"token_endpoint":                        d.TokenEndpoint,
		"jwks_uri":                              d.JWKSURI,
		"end_session_endpoint":                  d.EndSessionEndpoint,
		"dockio_catalog_endpoint":               d.CatalogEndpoint,
		"dockio_effective_permissions_endpoint": d.EffectivePermissionsEndpoint,
		"dockio_connect_endpoint":               d.ConnectEndpoint,
		"dockio_connect_token_endpoint":         d.ConnectTokenEndpoint,
		"dockio_connection_endpoint":            d.ConnectionEndpoint,
	}
}

// FetchDiscovery reads and validates base's OpenID configuration.
//
// Validation is the point. The issuer must be base itself (origin AND path), and
// every endpoint must sit on base's origin over https (loopback http excepted).
// The browser is sent to one of these endpoints and the client secret to another;
// a document that names a foreign host for either is refused outright.
func FetchDiscovery(ctx context.Context, hc *http.Client, base string) (Discovery, error) {
	if err := CheckSecure(base); err != nil {
		return Discovery{}, err
	}
	var d Discovery
	if err := getJSON(ctx, hc, strings.TrimRight(base, "/")+"/.well-known/openid-configuration", &d); err != nil {
		return Discovery{}, err
	}
	if !SameIssuer(d.Issuer, base) {
		return Discovery{}, fmt.Errorf("%w: discovery at %q names issuer %q", ErrBadURL, base, d.Issuer)
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return Discovery{}, fmt.Errorf("%w: discovery at %q lacks the authorization, token or jwks endpoint", ErrBadURL, base)
	}
	for name, e := range d.endpoints() {
		if e == "" {
			continue
		}
		if err := CheckOnOrigin(base, e); err != nil {
			return Discovery{}, fmt.Errorf("%s: %w", name, err)
		}
	}
	return d, nil
}
