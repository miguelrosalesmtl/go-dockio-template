// Package dockiotest is an in-process fake døckio station for tests.
//
// It speaks the same wire as the real one for everything this application uses:
// discovery (station and tenant), app connect (§14), the authorization and token
// endpoints, JWKS, end-session, the connection endpoint, the permission catalog
// and the effective-permissions lookup. It signs id tokens, back-channel logout
// tokens and connection-revoked notices with a test key.
//
// It is deliberately small and literal: a test configures what the "person" in
// front of døckio would do (approve or deny, which tenant, who signs in) and then
// drives the application. Every request it receives can be inspected afterwards.
package dockiotest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miguelrosalesmtl/go-dockio-template/internal/dockio"
)

// Person is somebody who can sign in at the fake station.
type Person struct {
	UID        string
	Username   string
	Email      string
	GivenName  string
	FamilyName string
	Realms     []string
	Disabled   bool
}

// Client is an OIDC client the station has issued.
type Client struct {
	ID           string
	Secrets      []string // live secrets; a renewal keeps the old one too
	Tenant       string
	ConnectionID string
	ExpiresAt    time.Time // zero: never
	Revoked      bool
}

// Station is the fake.
type Station struct {
	URL string

	t   testing.TB
	srv *httptest.Server
	key *rsa.PrivateKey
	kid string

	mu sync.Mutex

	// NoConnect makes the station predate §14: no connect fields in discovery.
	NoConnect bool
	// ConnectDenies makes the operator click "Cancel" in døckio.
	ConnectDenies bool
	// ConnectTenant is the tenant the operator picks. Default "acme".
	ConnectTenant string
	// ConnectRealm is the realm the grant reports. Default "app".
	ConnectRealm string
	// GrantHook lets a test tamper with the grant before it is sent.
	GrantHook func(g map[string]any)
	// SignIn is who signs in at /authorize.
	SignIn *Person
	// IssuerOverride makes id tokens claim another issuer.
	IssuerOverride string

	clients       map[string]*Client
	connectCodes  map[string]connectCode
	authCodes     map[string]authCode
	appTokens     map[string]appToken
	people        map[string]*Person             // by username
	effective     map[string]map[string][]string // username -> realm -> keys
	catalog       *dockio.Catalog
	Disconnects   int
	CatalogPuts   int
	EffectiveHits int
}

type connectCode struct {
	challenge, returnURI, tenant, renew string
}

type authCode struct {
	clientID, redirectURI, challenge, nonce, realm string
	person                                         Person
}

type appToken struct {
	clientID string
	scopes   []string
}

// New starts a station; it stops when the test ends.
func New(t testing.TB) *Station {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s := &Station{
		t: t, key: key, kid: "test-key-1",
		ConnectTenant: "acme", ConnectRealm: "app",
		clients: map[string]*Client{}, connectCodes: map[string]connectCode{},
		authCodes: map[string]authCode{}, appTokens: map[string]appToken{},
		people: map[string]*Person{}, effective: map[string]map[string][]string{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery(""))
	mux.HandleFunc("GET /t/{tenant}/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		s.discovery(r.PathValue("tenant"))(w, r)
	})
	mux.HandleFunc("GET /jwks", s.jwks)
	mux.HandleFunc("GET /connect", s.connect)
	mux.HandleFunc("POST /api/connect/token", s.connectToken)
	mux.HandleFunc("GET /authorize", s.authorize)
	mux.HandleFunc("POST /token", s.token)
	mux.HandleFunc("GET /end-session", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("DELETE /api/rp/connection", s.deleteConnection)
	mux.HandleFunc("PUT /api/rp/catalog", s.putCatalog)
	mux.HandleFunc("GET /api/rp/catalog", s.getCatalog)
	mux.HandleFunc("GET /api/rp/effective/{username}", s.getEffective)
	s.srv = httptest.NewServer(mux)
	s.URL = s.srv.URL
	t.Cleanup(s.srv.Close)
	return s
}

// Close stops the station early, to simulate an outage.
func (s *Station) Close() { s.srv.Close() }

// Issuer returns the issuer of tenant.
func (s *Station) Issuer(tenant string) string { return s.URL + "/t/" + tenant }

// ---------------------------------------------------------------- test controls

// AddPerson registers somebody who exists in døckio.
func (s *Station) AddPerson(p Person) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := p
	cp.Realms = slices.Clone(p.Realms) // the test's Person must not change under it
	s.people[p.Username] = &cp
}

// SetEffective sets what username may do in realm, as døckio would compute it.
func (s *Station) SetEffective(username, realm string, keys ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.effective[username] == nil {
		s.effective[username] = map[string][]string{}
	}
	s.effective[username][realm] = keys
}

// RemoveFromRealm takes username out of realm, as a døckio admin would.
func (s *Station) RemoveFromRealm(username, realm string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.people[username]; p != nil {
		p.Realms = slices.DeleteFunc(slices.Clone(p.Realms), func(r string) bool { return r == realm })
	}
	delete(s.effective[username], realm)
}

// RegisterClient creates a client directly, as a manual setup in døckio would.
func (s *Station) RegisterClient(tenant string) (id, secret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, secret = "cl_"+rnd(6), "sec_"+rnd(12)
	s.clients[id] = &Client{ID: id, Secrets: []string{secret}, Tenant: tenant}
	return id, secret
}

// ClientByID returns a copy of a client's state.
func (s *Station) ClientByID(id string) Client {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.clients[id]; c != nil {
		return *c
	}
	return Client{}
}

// ExpireClient makes the client's secret expired.
func (s *Station) ExpireClient(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.clients[id]; c != nil {
		c.ExpiresAt = time.Now().Add(-time.Hour)
	}
}

// RevokeClient revokes the client's connection, as døckio's console would. It
// does not send the notice; SignRevocation builds it.
func (s *Station) RevokeClient(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.clients[id]; c != nil {
		c.Revoked = true
	}
}

// Catalog returns the last catalog published, or nil.
func (s *Station) Catalog() *dockio.Catalog {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.catalog
}

// SignRevocation builds the connection-revoked notice døckio would POST.
func (s *Station) SignRevocation(clientID string, issuedAt time.Time) string {
	c := s.ClientByID(clientID)
	return s.Sign("connection-revoked+jwt", map[string]any{
		"iss": s.Issuer(c.Tenant), "aud": clientID, "iat": issuedAt.Unix(),
		"exp": issuedAt.Add(15 * time.Minute).Unix(), "jti": rnd(8),
		"connection_id": c.ConnectionID, "reason": "revoked_by_admin",
	})
}

// SignLogout builds a back-channel logout token.
func (s *Station) SignLogout(clientID string, claims map[string]any) string {
	c := s.ClientByID(clientID)
	now := time.Now()
	base := map[string]any{
		"iss": s.Issuer(c.Tenant), "aud": clientID, "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
		"jti":    rnd(8),
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	}
	for k, v := range claims {
		base[k] = v
	}
	return s.Sign("logout+jwt", base)
}

// Sign makes an RS256 JWS with the station's key.
func (s *Station) Sign(typ string, claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": s.kid, "typ": typ})
	c, _ := json.Marshal(claims)
	input := b64(h) + "." + b64(c)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		s.t.Fatal(err)
	}
	return input + "." + b64(sig)
}

// ---------------------------------------------------------------- endpoints

func (s *Station) discovery(tenant string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		issuer := s.URL
		if tenant != "" {
			issuer = s.Issuer(tenant)
		}
		d := map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                s.URL + "/authorize",
			"token_endpoint":                        s.URL + "/token",
			"jwks_uri":                              s.URL + "/jwks",
			"end_session_endpoint":                  s.URL + "/end-session",
			"dockio_catalog_endpoint":               s.URL + "/api/rp/catalog",
			"dockio_effective_permissions_endpoint": s.URL + "/api/rp/effective/{username}",
		}
		if !s.NoConnect {
			d["dockio_connect_endpoint"] = s.URL + "/connect"
			d["dockio_connect_token_endpoint"] = s.URL + "/api/connect/token"
			d["dockio_connection_endpoint"] = s.URL + "/api/rp/connection"
			d["dockio_connect_expiry_days"] = []int{90, 180, 365}
		}
		writeJSON(w, http.StatusOK, d)
	}
}

func (s *Station) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := s.key.PublicKey
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": s.kid,
		"n": b64(pub.N.Bytes()), "e": b64(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

// connect plays the operator approving (or cancelling) in døckio's browser UI.
func (s *Station) connect(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ret, state := q.Get("return_uri"), q.Get("state")
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || ret == "" ||
		len(state) < 16 || len(state) > 512 || q.Get("manifest_uri") == "" {
		http.Error(w, "bad connect request", http.StatusBadRequest)
		return
	}
	if !dockio.SameOrigin(ret, q.Get("manifest_uri")) {
		http.Error(w, "return_uri is not on the manifest's origin", http.StatusBadRequest)
		return
	}
	target, _ := url.Parse(ret)
	v := target.Query()
	v.Set("state", state)
	if s.ConnectDenies {
		v.Set("error", "access_denied")
	} else {
		code := rnd(16)
		s.mu.Lock()
		s.connectCodes[code] = connectCode{
			challenge: q.Get("code_challenge"), returnURI: ret,
			tenant: s.ConnectTenant, renew: q.Get("connection"),
		}
		s.mu.Unlock()
		v.Set("code", code)
	}
	target.RawQuery = v.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound) //nolint:gosec // a test fake: it redirects where the test asked
}

func (s *Station) connectToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code, CodeVerifier, ReturnURI string
	}
	var raw map[string]string
	if json.NewDecoder(r.Body).Decode(&raw) != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "")
		return
	}
	in.Code, in.CodeVerifier, in.ReturnURI = raw["code"], raw["code_verifier"], raw["return_uri"]

	s.mu.Lock()
	defer s.mu.Unlock()
	cc, ok := s.connectCodes[in.Code]
	delete(s.connectCodes, in.Code) // first use spends it, success or not
	if !ok || cc.returnURI != in.ReturnURI || dockio.Challenge(in.CodeVerifier) != cc.challenge {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "")
		return
	}

	var c *Client
	if cc.renew != "" {
		for _, x := range s.clients {
			if x.ConnectionID == cc.renew {
				c = x
			}
		}
	}
	if c == nil {
		c = &Client{ID: "cl_" + rnd(6), Tenant: cc.tenant, ConnectionID: "conn_" + rnd(6)}
		s.clients[c.ID] = c
	}
	secret := "sec_" + rnd(12)
	c.Secrets = append(c.Secrets, secret) // the previous one keeps working for a while
	c.Revoked = false
	c.ExpiresAt = time.Now().Add(365 * 24 * time.Hour)

	g := map[string]any{
		"connection_id": c.ConnectionID, "issuer": s.Issuer(c.Tenant),
		"client_id": c.ID, "client_secret": secret, "client_secret_expires_at": c.ExpiresAt.Unix(),
		"tenant": map[string]string{"name": strings.ToUpper(c.Tenant[:1]) + c.Tenant[1:], "address": c.Tenant},
		"realm":  s.ConnectRealm, "app_key": "app",
		"switches":   map[string]bool{"spanning": true, "provisioning": true, "first_party": false},
		"manage_uri": s.Issuer(c.Tenant) + "/connected-apps?connection=" + c.ConnectionID,
	}
	if s.GrantHook != nil {
		s.GrantHook(g)
	}
	writeJSON(w, http.StatusOK, g)
}

// authorize plays somebody signing in at døckio.
func (s *Station) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.mu.Lock()
	c := s.clients[q.Get("client_id")]
	person := s.SignIn
	s.mu.Unlock()
	if c == nil || q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" {
		http.Error(w, "bad authorization request", http.StatusBadRequest)
		return
	}
	target, _ := url.Parse(q.Get("redirect_uri"))
	v := target.Query()
	v.Set("state", q.Get("state"))
	realm := q.Get("dockio_realm")
	switch {
	case person == nil || person.Disabled:
		v.Set("error", "access_denied")
	case realm != "" && !slices.Contains(person.Realms, realm):
		v.Set("error", "access_denied")
	default:
		code := rnd(16)
		s.mu.Lock()
		s.authCodes[code] = authCode{
			clientID: c.ID, redirectURI: q.Get("redirect_uri"), challenge: q.Get("code_challenge"),
			nonce: q.Get("nonce"), realm: realm, person: *person,
		}
		s.mu.Unlock()
		v.Set("code", code)
	}
	target.RawQuery = v.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound) //nolint:gosec // a test fake: it redirects where the test asked
}

func (s *Station) authenticateClient(r *http.Request) (*Client, string) {
	id, secret, ok := r.BasicAuth()
	if !ok {
		return nil, "invalid_client"
	}
	id, _ = url.QueryUnescape(id)
	secret, _ = url.QueryUnescape(secret)
	c := s.clients[id]
	if c == nil || !slices.Contains(c.Secrets, secret) || c.Revoked {
		return nil, "invalid_client"
	}
	if !c.ExpiresAt.IsZero() && time.Now().After(c.ExpiresAt) {
		return nil, "client_secret_expired"
	}
	return c, ""
}

func (s *Station) token(w http.ResponseWriter, r *http.Request) {
	if r.ParseForm() != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, problem := s.authenticateClient(r)
	switch problem {
	case "invalid_client":
		oauthError(w, http.StatusUnauthorized, "invalid_client", "")
		return
	case "client_secret_expired":
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client_secret_expired")
		return
	}

	switch r.PostForm.Get("grant_type") {
	case "client_credentials":
		tok := "at_" + rnd(12)
		s.appTokens[tok] = appToken{clientID: c.ID, scopes: strings.Fields(r.PostForm.Get("scope"))}
		writeJSON(w, http.StatusOK, map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": 3600})

	case "authorization_code":
		code := r.PostForm.Get("code")
		ac, ok := s.authCodes[code]
		delete(s.authCodes, code)
		if !ok || ac.clientID != c.ID || ac.redirectURI != r.PostForm.Get("redirect_uri") ||
			dockio.Challenge(r.PostForm.Get("code_verifier")) != ac.challenge {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "")
			return
		}
		now := time.Now()
		iss := s.Issuer(c.Tenant)
		if s.IssuerOverride != "" {
			iss = s.IssuerOverride
		}
		claims := map[string]any{
			"iss": iss, "aud": c.ID, "sub": ac.person.Username, "uid": ac.person.UID,
			"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "auth_time": now.Unix(),
			"nonce": ac.nonce, "email": ac.person.Email, "given_name": ac.person.GivenName,
			"family_name": ac.person.FamilyName, "preferred_username": ac.person.Username,
			"dockio_realms": ac.person.Realms, "sid": "sid_" + rnd(6),
		}
		if ac.realm != "" {
			claims["realm"] = ac.realm
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": "at_" + rnd(12), "token_type": "Bearer", "expires_in": 300,
			"id_token": s.Sign("JWT", claims), "scope": "openid profile email groups",
		})

	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "")
	}
}

// bearer resolves the application token on an RP API call.
func (s *Station) bearer(r *http.Request, scope string) *Client {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return nil
	}
	at, ok := s.appTokens[tok]
	if !ok || !slices.Contains(at.scopes, scope) {
		return nil
	}
	c := s.clients[at.clientID]
	if c == nil || c.Revoked {
		return nil
	}
	return c
}

func (s *Station) deleteConnection(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Disconnects++
	c := s.bearer(r, "dockio:connection")
	if c == nil {
		oauthError(w, http.StatusUnauthorized, "invalid_token", "")
		return
	}
	if c.ConnectionID == "" || c.Revoked {
		http.NotFound(w, r)
		return
	}
	c.Revoked = true
	writeJSON(w, http.StatusOK, map[string]any{"connectionId": c.ConnectionID, "revoked": true})
}

func (s *Station) putCatalog(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bearer(r, "dockio:catalog") == nil {
		oauthError(w, http.StatusUnauthorized, "invalid_token", "")
		return
	}
	var cat dockio.Catalog
	if json.NewDecoder(r.Body).Decode(&cat) != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "")
		return
	}
	if s.catalog != nil && cat.Version < s.catalog.Version {
		oauthError(w, http.StatusConflict, "version_conflict", "")
		return
	}
	s.CatalogPuts++
	unchanged := s.catalog != nil && s.catalog.Version == cat.Version
	s.catalog = &cat
	writeJSON(w, http.StatusOK, map[string]any{"version": cat.Version, "active": len(cat.Permissions), "unchanged": unchanged})
}

func (s *Station) getCatalog(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bearer(r, "dockio:catalog") == nil {
		oauthError(w, http.StatusUnauthorized, "invalid_token", "")
		return
	}
	writeJSON(w, http.StatusOK, s.catalog)
}

func (s *Station) getEffective(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.EffectiveHits++
	if s.bearer(r, "dockio:assignments") == nil {
		oauthError(w, http.StatusUnauthorized, "invalid_token", "")
		return
	}
	username := r.PathValue("username")
	p := s.people[username]
	if p == nil {
		http.NotFound(w, r)
		return
	}
	realm := r.URL.Query().Get("realm")
	keys := s.effective[username][realm]
	if keys == nil {
		keys = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"username": p.Username, "id": p.UID, "disabled": p.Disabled, "keys": keys, "realms": p.Realms,
	})
}

// ---------------------------------------------------------------- helpers

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	body := map[string]string{"error": code}
	if desc != "" {
		body["error_description"] = desc
	}
	writeJSON(w, status, body)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func rnd(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
