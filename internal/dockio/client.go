package dockio

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Client is the application as one døckio relying party: one client id and
// secret, issued under one tenant issuer. Everything that needs those
// credentials -- sign-in, sign-out, the permission catalog, permission lookups,
// revocation notices, disconnect -- goes through it.
//
// It is safe for concurrent use. Build a new one whenever the stored settings
// change; identity.Service does that.
type Client struct {
	cfg  Config
	disc Discovery
	http *http.Client
	keys *keySet

	appTokens appTokenCache
	jtis      jtiSet
	now       func() time.Time
}

// Config is what a Client is built from.
type Config struct {
	Issuer       string // the TENANT issuer from the grant (or typed by hand)
	ClientID     string
	ClientSecret string
	HTTP         *http.Client // nil: NewHTTPClient()
}

// NewClient reads the issuer's discovery document and returns a Client.
func NewClient(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" {
		return nil, errors.New("dockio: an issuer and a client id are required")
	}
	if cfg.HTTP == nil {
		cfg.HTTP = NewHTTPClient()
	}
	d, err := FetchDiscovery(ctx, cfg.HTTP, cfg.Issuer)
	if err != nil {
		return nil, err
	}
	return &Client{
		cfg: cfg, disc: d, http: cfg.HTTP,
		keys: newKeySet(d.JWKSURI, cfg.HTTP),
		jtis: jtiSet{seen: map[string]time.Time{}},
		now:  time.Now,
	}, nil
}

// Issuer returns the tenant issuer this client belongs to.
func (c *Client) Issuer() string { return c.cfg.Issuer }

// ClientID returns the client id.
func (c *Client) ClientID() string { return c.cfg.ClientID }

// Discovery returns the issuer's validated discovery document.
func (c *Client) Discovery() Discovery { return c.disc }

// ---------------------------------------------------------------- sign-in

// DefaultScopes are asked for at sign-in.
var DefaultScopes = []string{"openid", "profile", "email", "groups"}

// AuthRequest is one sign-in attempt.
type AuthRequest struct {
	RedirectURI string
	State       string
	Nonce       string
	Challenge   string // PKCE S256
	// Realm asks døckio to sign the person in to one realm: døckio shows that
	// realm's branding, and the id token's realm claim must come back equal to it.
	Realm     string
	UILocales string
	Scopes    []string
}

// AuthCodeURL is where the browser goes to sign in.
func (c *Client) AuthCodeURL(r AuthRequest) string {
	scopes := r.Scopes
	if len(scopes) == 0 {
		scopes = DefaultScopes
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.cfg.ClientID},
		"redirect_uri":          {r.RedirectURI},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {r.State},
		"nonce":                 {r.Nonce},
		"code_challenge":        {r.Challenge},
		"code_challenge_method": {"S256"},
	}
	if r.Realm != "" {
		q.Set("dockio_realm", r.Realm) // ASSUMPTION: see docs/dockio.md
	}
	if r.UILocales != "" {
		q.Set("ui_locales", r.UILocales)
	}
	return c.disc.AuthorizationEndpoint + "?" + q.Encode()
}

// Tokens is a token endpoint answer.
type Tokens struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	IDToken     string `json:"id_token,omitempty"`
	Scope       string `json:"scope"`
}

// ErrSecretExpired is the token endpoint saying the client secret has expired
// (invalid_client + client_secret_expired). It means "renew the connection", not
// "the secret is wrong" -- show it that way.
var ErrSecretExpired = errors.New("dockio: the client secret has expired")

// Exchange trades an authorization code for tokens (client_secret_basic, PKCE).
func (c *Client) Exchange(ctx context.Context, code, redirectURI, verifier string) (Tokens, error) {
	return c.token(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	})
}

func (c *Client) token(ctx context.Context, form url.Values) (Tokens, error) {
	u, err := ASCIIURL(c.disc.TokenEndpoint)
	if err != nil {
		return Tokens{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return Tokens{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// RFC 6749 §2.3.1: form-encode, then Basic. ASSUMPTION: see docs/dockio.md.
	req.SetBasicAuth(url.QueryEscape(c.cfg.ClientID), url.QueryEscape(c.cfg.ClientSecret))

	var t Tokens
	if _, err := call(c.http, req, &t); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Code == "invalid_client" && apiErr.Description == "client_secret_expired" {
			return Tokens{}, ErrSecretExpired
		}
		return Tokens{}, err
	}
	return t, nil
}

// IDClaims are the id token claims sign-in uses.
type IDClaims struct {
	Subject           string   // sub: the username. It can change -- never link by it
	UID               string   // the døckio account id. It never changes -- link by this
	PreferredUsername string   // preferred_username, when sent
	Email             string   // a copy; never an identifier
	GivenName         string   //
	FamilyName        string   //
	Name              string   //
	Locale            string   //
	Realm             string   // the realm signed in to, when the attempt asked for one
	Realms            []string // every realm the person belongs to under this client
	SID               string   // the døckio session id, for back-channel logout
	AuthTime          int64
}

// Username is the name the effective-permissions endpoint is asked about.
func (c IDClaims) Username() string {
	if c.PreferredUsername != "" {
		return c.PreferredUsername
	}
	return c.Subject
}

// VerifyIDToken checks an id token for this client and attempt: signature,
// issuer (origin AND path), audience, lifetime, nonce, and the presence of uid.
func (c *Client) VerifyIDToken(ctx context.Context, raw, nonce string) (IDClaims, error) {
	var claims struct {
		registeredClaims
		Nonce             string   `json:"nonce"`
		UID               string   `json:"uid"` // ASSUMPTION: see docs/dockio.md
		PreferredUsername string   `json:"preferred_username"`
		Email             string   `json:"email"`
		GivenName         string   `json:"given_name"`
		FamilyName        string   `json:"family_name"`
		Name              string   `json:"name"`
		Locale            string   `json:"locale"`
		Realm             string   `json:"realm"`
		Realms            []string `json:"dockio_realms"` // ASSUMPTION: see docs/dockio.md
		SID               string   `json:"sid"`
		AuthTime          int64    `json:"auth_time"`
	}
	if err := c.keys.verifyJWS(ctx, raw, "", &claims); err != nil {
		return IDClaims{}, err
	}
	switch {
	case !SameIssuer(claims.Iss, c.cfg.Issuer):
		return IDClaims{}, invalidToken("issuer %q", claims.Iss)
	case !claims.audienceIs(c.cfg.ClientID):
		return IDClaims{}, invalidToken("issued for another client")
	case nonce == "" || claims.Nonce != nonce:
		return IDClaims{}, invalidToken("nonce mismatch")
	case claims.Sub == "":
		return IDClaims{}, invalidToken("no subject")
	case claims.UID == "":
		return IDClaims{}, invalidToken("no uid: accounts are linked by uid, never by sub")
	}
	if err := claims.checkTimes(c.now()); err != nil {
		return IDClaims{}, err
	}
	return IDClaims{
		Subject: claims.Sub, UID: claims.UID, PreferredUsername: claims.PreferredUsername,
		Email: claims.Email, GivenName: claims.GivenName, FamilyName: claims.FamilyName,
		Name: claims.Name, Locale: claims.Locale, Realm: claims.Realm, Realms: claims.Realms,
		SID: claims.SID, AuthTime: claims.AuthTime,
	}, nil
}

// EndSessionURL is where the browser goes to end the døckio session too
// (RP-initiated logout). It is "" when the station publishes no such endpoint.
func (c *Client) EndSessionURL(idTokenHint, postLogoutRedirectURI string) string {
	if c.disc.EndSessionEndpoint == "" {
		return ""
	}
	q := url.Values{"client_id": {c.cfg.ClientID}}
	if idTokenHint != "" {
		q.Set("id_token_hint", idTokenHint)
	}
	if postLogoutRedirectURI != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirectURI)
	}
	return c.disc.EndSessionEndpoint + "?" + q.Encode()
}

// ---------------------------------------------------------------- back-channel logout

// LogoutClaims identify whose sessions a back-channel logout ends.
type LogoutClaims struct {
	Subject string // sub
	UID     string // uid, when sent -- preferred: it never changes
	SID     string // sid: one døckio session
	Realm   string // dockio_realm: only that realm's sessions, when sent
}

const backchannelEvent = "http://schemas.openid.net/event/backchannel-logout"

// VerifyLogoutToken checks a back-channel logout token (typ logout+jwt) and
// refuses a replay of its jti for ten minutes.
//
// The jti memory is per process. Behind several replicas, a replay to another
// replica is not caught here -- but a logout replayed is still a logout, so the
// worst case is a session ended twice.
func (c *Client) VerifyLogoutToken(ctx context.Context, raw string) (LogoutClaims, error) {
	var claims struct {
		registeredClaims
		Events map[string]json.RawMessage `json:"events"`
		Nonce  *json.RawMessage           `json:"nonce"`
		UID    string                     `json:"uid"` // ASSUMPTION: see docs/dockio.md
		SID    string                     `json:"sid"`
		Realm  string                     `json:"dockio_realm"` // ASSUMPTION: see docs/dockio.md
	}
	if err := c.keys.verifyJWS(ctx, raw, "logout+jwt", &claims); err != nil {
		return LogoutClaims{}, err
	}
	switch {
	case !SameIssuer(claims.Iss, c.cfg.Issuer):
		return LogoutClaims{}, invalidToken("issuer %q", claims.Iss)
	case !claims.audienceIs(c.cfg.ClientID):
		return LogoutClaims{}, invalidToken("issued for another client")
	case claims.Events[backchannelEvent] == nil:
		return LogoutClaims{}, invalidToken("not a back-channel logout event")
	case claims.Nonce != nil:
		return LogoutClaims{}, invalidToken("a logout token must not carry a nonce")
	case claims.Sub == "" && claims.SID == "":
		return LogoutClaims{}, invalidToken("neither sub nor sid")
	case claims.Jti == "":
		return LogoutClaims{}, invalidToken("no jti")
	}
	if err := claims.checkTimes(c.now()); err != nil {
		return LogoutClaims{}, err
	}
	if !c.jtis.claim(claims.Jti, c.now()) {
		return LogoutClaims{}, invalidToken("replayed jti")
	}
	return LogoutClaims{Subject: claims.Sub, UID: claims.UID, SID: claims.SID, Realm: claims.Realm}, nil
}

// ReleaseJTI forgets a logout token's jti, so døckio's retry is not refused as a
// replay after the application failed to act on the first delivery.
func (c *Client) ReleaseJTI(raw string) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return
	}
	var claims registeredClaims
	if decodeSegment(parts[1], &claims) == nil {
		c.jtis.release(claims.Jti)
	}
}

type jtiSet struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

const jtiWindow = 10 * time.Minute

func (s *jtiSet) claim(jti string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, at := range s.seen {
		if now.Sub(at) > jtiWindow {
			delete(s.seen, k)
		}
	}
	if _, dup := s.seen[jti]; dup {
		return false
	}
	s.seen[jti] = now
	return true
}

func (s *jtiSet) release(jti string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.seen, jti)
}

// ---------------------------------------------------------------- revocation notices

// Revocation is a verified connection-revoked notice.
type Revocation struct {
	ConnectionID string
	Reason       string
	IssuedAt     time.Time
	JTI          string
}

// VerifyRevocation checks the token døckio POSTs to the manifest's revocation_uri
// when a connection is revoked from its console: typ connection-revoked+jwt,
// signed by THIS client's issuer, aud = this client id, unexpired.
//
// Replay protection is the caller's: identity accepts a notice only when its iat
// is after the last connect, which needs the database.
func (c *Client) VerifyRevocation(ctx context.Context, raw string) (Revocation, error) {
	var claims struct {
		registeredClaims
		ConnectionID string `json:"connection_id"`
		Reason       string `json:"reason"`
	}
	if err := c.keys.verifyJWS(ctx, raw, "connection-revoked+jwt", &claims); err != nil {
		return Revocation{}, err
	}
	switch {
	case !SameIssuer(claims.Iss, c.cfg.Issuer):
		return Revocation{}, invalidToken("issuer %q", claims.Iss)
	case !claims.audienceIs(c.cfg.ClientID):
		return Revocation{}, invalidToken("issued for another client")
	case claims.ConnectionID == "":
		return Revocation{}, invalidToken("no connection_id")
	}
	if err := claims.checkTimes(c.now()); err != nil {
		return Revocation{}, err
	}
	return Revocation{
		ConnectionID: claims.ConnectionID, Reason: claims.Reason,
		IssuedAt: time.Unix(*claims.Iat, 0), JTI: claims.Jti,
	}, nil
}

// ---------------------------------------------------------------- application token

// The scopes of the application token used for the RP API. dockio:connection is
// separate and is asked for only to disconnect: it is never a default scope.
//
// ASSUMPTION: see docs/dockio.md.
const (
	scopeRP         = "dockio:catalog dockio:assignments"
	scopeConnection = "dockio:connection"
)

type appTokenCache struct {
	mu     sync.Mutex
	tokens map[string]cachedToken
}

type cachedToken struct {
	value   string
	expires time.Time
}

// AppToken returns a client_credentials token for scope, cached until a minute
// before it expires.
func (c *Client) AppToken(ctx context.Context, scope string) (string, error) {
	c.appTokens.mu.Lock()
	defer c.appTokens.mu.Unlock()
	if t, ok := c.appTokens.tokens[scope]; ok && c.now().Before(t.expires) {
		return t.value, nil
	}
	tok, err := c.token(ctx, url.Values{"grant_type": {"client_credentials"}, "scope": {scope}})
	if err != nil {
		return "", err
	}
	if c.appTokens.tokens == nil {
		c.appTokens.tokens = map[string]cachedToken{}
	}
	ttl := time.Duration(tok.ExpiresIn)*time.Second - time.Minute
	if ttl > 0 {
		c.appTokens.tokens[scope] = cachedToken{value: tok.AccessToken, expires: c.now().Add(ttl)}
	}
	return tok.AccessToken, nil
}

func (c *Client) dropAppToken(scope string) {
	c.appTokens.mu.Lock()
	defer c.appTokens.mu.Unlock()
	delete(c.appTokens.tokens, scope)
}

// rp calls the RP API with the application token, retrying once with a fresh
// token after a 401 (the cached one was revoked early).
func (c *Client) rp(ctx context.Context, method, endpoint, scope string, in, out any) (int, error) {
	for attempt := 0; ; attempt++ {
		tok, err := c.AppToken(ctx, scope)
		if err != nil {
			return 0, err
		}
		status, err := sendJSON(ctx, c.http, method, endpoint, tok, in, out)
		if status == http.StatusUnauthorized && attempt == 0 {
			c.dropAppToken(scope)
			continue
		}
		return status, err
	}
}

// ---------------------------------------------------------------- disconnect

// Disconnect revokes this client's connection at døckio. It reports whether døckio
// had a live connection to revoke: false (and no error) for a 404, and also when
// the client's own credentials are already expired or revoked -- in both cases
// the connection is already as dead as it can get.
func (c *Client) Disconnect(ctx context.Context) (bool, error) {
	endpoint := c.disc.ConnectionEndpoint
	if endpoint == "" {
		// A tenant's discovery may not repeat the station-level §14 fields; the
		// station's own document, on the same origin, has them.
		origin, err := Origin(c.cfg.Issuer)
		if err != nil {
			return false, err
		}
		station, err := FetchDiscovery(ctx, c.http, origin)
		if err != nil {
			return false, err
		}
		if station.ConnectionEndpoint == "" {
			return false, ErrConnectNotSupported
		}
		endpoint = station.ConnectionEndpoint
	}

	for attempt := 0; ; attempt++ {
		tok, err := c.AppToken(ctx, scopeConnection)
		if err != nil {
			var apiErr *APIError
			if errors.Is(err, ErrSecretExpired) || (errors.As(err, &apiErr) && (apiErr.Status == 400 || apiErr.Status == 401)) {
				return false, nil
			}
			return false, err
		}
		var out struct {
			Revoked bool `json:"revoked"`
		}
		status, err := sendJSON(ctx, c.http, http.MethodDelete, endpoint, tok, nil, &out)
		switch {
		case status == http.StatusUnauthorized && attempt == 0:
			// A cached token can outlive the connection it was issued under. Ask
			// for a fresh one: if the credentials are dead too, that is the answer.
			c.dropAppToken(scopeConnection)
			continue
		case status == http.StatusNotFound || status == http.StatusUnauthorized:
			return false, nil
		case err != nil:
			return false, err
		}
		return out.Revoked, nil
	}
}

// ---------------------------------------------------------------- catalog

// Catalog is the set of permission keys the application defines. døckio stores
// roles and grants over these keys; it never invents keys of its own.
type Catalog struct {
	Version     uint64       `json:"version"`
	Permissions []Permission `json:"permissions"`
}

// Permission is one catalog entry.
type Permission struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
}

// SyncReport is døckio's answer to a catalog sync.
type SyncReport struct {
	Version    uint64 `json:"version"`
	Active     int    `json:"active"`
	Deprecated int    `json:"deprecated"`
	Unchanged  bool   `json:"unchanged"`
}

// ErrCatalogVersionConflict means døckio already holds a NEWER catalog: this is
// an older build (a rolled-back deploy). It is not fatal -- keys this build does
// not know stay deprecated-not-deleted in døckio -- but it is worth a warning.
var ErrCatalogVersionConflict = errors.New("dockio: døckio holds a newer permission catalog")

// SyncCatalog publishes the catalog. ASSUMPTION: the shape; see docs/dockio.md.
// A key the application drops is deprecated by
// døckio, never deleted, so a rollback keeps its assignments.
func (c *Client) SyncCatalog(ctx context.Context, cat Catalog) (SyncReport, error) {
	if c.disc.CatalogEndpoint == "" {
		return SyncReport{}, fmt.Errorf("dockio: %s publishes no catalog endpoint", c.cfg.Issuer)
	}
	var rep SyncReport
	status, err := c.rp(ctx, http.MethodPut, c.disc.CatalogEndpoint, scopeRP, cat, &rep)
	if status == http.StatusConflict {
		return SyncReport{}, ErrCatalogVersionConflict
	}
	return rep, err
}

// ---------------------------------------------------------------- effective permissions

// Effective is what a person may do in one realm, as døckio computes it from their
// roles there -- held directly or through a group.
type Effective struct {
	Username string   `json:"username"`
	ID       string   `json:"id"` // the uid; must equal the linked uid
	Disabled bool     `json:"disabled"`
	Keys     []string `json:"keys"`
	Realms   []string `json:"realms"` // ASSUMPTION: see docs/dockio.md
}

// ErrNoSuchPerson is døckio not knowing the username at all.
var ErrNoSuchPerson = errors.New("dockio: no such person")

// EffectiveIn asks døckio for username's effective permission keys in realm.
func (c *Client) EffectiveIn(ctx context.Context, username, realm string) (Effective, error) {
	if c.disc.EffectivePermissionsEndpoint == "" {
		return Effective{}, fmt.Errorf("dockio: %s publishes no effective-permissions endpoint", c.cfg.Issuer)
	}
	endpoint := strings.Replace(c.disc.EffectivePermissionsEndpoint, "{username}", url.PathEscape(username), 1)
	if realm != "" {
		sep := "?"
		if strings.Contains(endpoint, "?") {
			sep = "&"
		}
		endpoint += sep + "realm=" + url.QueryEscape(realm) // ASSUMPTION: see docs/dockio.md
	}
	var e Effective
	status, err := c.rp(ctx, http.MethodGet, endpoint, scopeRP, nil, &e)
	if status == http.StatusNotFound {
		return Effective{}, ErrNoSuchPerson
	}
	return e, err
}
