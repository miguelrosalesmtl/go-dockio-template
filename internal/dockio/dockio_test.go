package dockio_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/miguelrosalesmtl/go-dockio-template/internal/dockio"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/dockio/dockiotest"
)

var ctx = context.Background()

// follow performs one browser hop without following the redirect, and returns
// the query of the Location døckio sent the browser to.
func follow(t *testing.T, rawURL string) url.Values {
	t.Helper()
	resp, err := dockio.NewHTTPClient().Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET %s: status %d, want 302", rawURL, resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc.Query()
}

func newClient(t *testing.T, st *dockiotest.Station, tenant string) *dockio.Client {
	t.Helper()
	id, secret := st.RegisterClient(tenant)
	c, err := dockio.NewClient(ctx, dockio.Config{Issuer: st.Issuer(tenant), ClientID: id, ClientSecret: secret})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// ---------------------------------------------------------------- origins

func TestUnicodeAndPunycodeSpellingsAreTheSameOrigin(t *testing.T) {
	if !dockio.SameOrigin("https://døck.io/t/acme", "https://xn--dck-0na.io") {
		t.Fatal("døck.io and xn--dck-0na.io should be the same origin")
	}
	if !dockio.SameIssuer("https://døck.io/t/acme/", "https://XN--DCK-0NA.io/t/acme") {
		t.Fatal("the same tenant issuer in two spellings should match")
	}
}

func TestTenantsOnOneStationAreDifferentIssuers(t *testing.T) {
	if dockio.SameIssuer("https://døck.io/t/acme", "https://døck.io/t/other") {
		t.Fatal("two tenants on one station compared equal: an origin-only check")
	}
}

func TestPlainHTTPIsAcceptedOnlyOnLoopback(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://døck.io":         true,
		"http://127.0.0.1:8080":   true,
		"http://localhost:9000/x": true,
		"http://døck.io":          false,
		"ftp://døck.io":           false,
	} {
		if got := dockio.CheckSecure(raw) == nil; got != ok {
			t.Errorf("CheckSecure(%q) accepted = %v, want %v", raw, got, ok)
		}
	}
}

// ---------------------------------------------------------------- discovery

func TestDiscoveryNamingAnotherIssuerIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"https://elsewhere.example","authorization_endpoint":"x","token_endpoint":"x","jwks_uri":"x"}`))
	}))
	defer srv.Close()
	if _, err := dockio.FetchDiscovery(ctx, dockio.NewHTTPClient(), srv.URL); !errors.Is(err, dockio.ErrBadURL) {
		t.Fatalf("err = %v, want ErrBadURL", err)
	}
}

func TestDiscoveryWithAForeignEndpointIsRefused(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"` + srv.URL + `","authorization_endpoint":"` + srv.URL + `/a",` +
			`"token_endpoint":"https://attacker.example/token","jwks_uri":"` + srv.URL + `/jwks"}`))
	}))
	defer srv.Close()
	_, err := dockio.FetchDiscovery(ctx, dockio.NewHTTPClient(), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "token_endpoint") {
		t.Fatalf("err = %v, want the token endpoint refused", err)
	}
}

func TestAStationWithoutConnectSaysSo(t *testing.T) {
	st := dockiotest.New(t)
	st.NoConnect = true
	d, err := dockio.FetchDiscovery(ctx, dockio.NewHTTPClient(), st.URL)
	if err != nil {
		t.Fatal(err)
	}
	if d.SupportsConnect() {
		t.Fatal("a station without the connect fields claims to support connect")
	}
}

// ---------------------------------------------------------------- app connect

func connectCode(t *testing.T, st *dockiotest.Station, pkce dockio.PKCE, returnURI string) (dockio.Discovery, string) {
	t.Helper()
	d, err := dockio.FetchDiscovery(ctx, dockio.NewHTTPClient(), st.URL)
	if err != nil {
		t.Fatal(err)
	}
	state, _ := dockio.RandomToken(32)
	q := follow(t, dockio.ConnectURL(d, dockio.ConnectRequest{
		ManifestURI: "http://127.0.0.1:1/api/v1/dockio/manifest", ReturnURI: returnURI,
		State: state, CodeChallenge: pkce.Challenge,
	}))
	if q.Get("state") != state {
		t.Fatalf("state came back as %q", q.Get("state"))
	}
	return d, q.Get("code")
}

const returnURI = "http://127.0.0.1:1/api/v1/auth/oidc/connect/callback"

func TestAConnectCodeBecomesCredentials(t *testing.T) {
	st := dockiotest.New(t)
	pkce, _ := dockio.NewPKCE()
	d, code := connectCode(t, st, pkce, returnURI)

	g, err := dockio.ExchangeConnectCode(ctx, dockio.NewHTTPClient(), d, code, pkce.Verifier, returnURI)
	if err != nil {
		t.Fatal(err)
	}
	if g.ClientID == "" || g.ClientSecret == "" || g.ConnectionID == "" || !dockio.SameIssuer(g.Issuer, st.Issuer("acme")) {
		t.Fatalf("incomplete grant: %+v", g)
	}
}

func TestAConnectCodeIsSpentByItsFirstUseEvenAFailedOne(t *testing.T) {
	st := dockiotest.New(t)
	pkce, _ := dockio.NewPKCE()
	d, code := connectCode(t, st, pkce, returnURI)

	if _, err := dockio.ExchangeConnectCode(ctx, dockio.NewHTTPClient(), d, code, "wrong-verifier", returnURI); !errors.Is(err, dockio.ErrInvalidGrant) {
		t.Fatalf("wrong verifier: err = %v, want ErrInvalidGrant", err)
	}
	if _, err := dockio.ExchangeConnectCode(ctx, dockio.NewHTTPClient(), d, code, pkce.Verifier, returnURI); !errors.Is(err, dockio.ErrInvalidGrant) {
		t.Fatalf("second use: err = %v, want ErrInvalidGrant", err)
	}
}

// ---------------------------------------------------------------- sign-in

const redirect = "http://127.0.0.1:1/api/v1/auth/oidc/callback"

func signIn(t *testing.T, st *dockiotest.Station, c *dockio.Client, realm string) (dockio.Tokens, string, error) {
	t.Helper()
	pkce, _ := dockio.NewPKCE()
	nonce, _ := dockio.RandomToken(16)
	state, _ := dockio.RandomToken(16)
	q := follow(t, c.AuthCodeURL(dockio.AuthRequest{
		RedirectURI: redirect, State: state, Nonce: nonce, Challenge: pkce.Challenge, Realm: realm,
	}))
	if q.Get("error") != "" {
		return dockio.Tokens{}, nonce, errors.New(q.Get("error"))
	}
	tok, err := c.Exchange(ctx, q.Get("code"), redirect, pkce.Verifier)
	return tok, nonce, err
}

var ana = dockiotest.Person{UID: "u-1", Username: "ana", Email: "ana@example.com", GivenName: "Ana", Realms: []string{"r-shop"}}

func TestSignInYieldsAVerifiedIdToken(t *testing.T) {
	st := dockiotest.New(t)
	st.SignIn = &ana
	c := newClient(t, st, "acme")

	tok, nonce, err := signIn(t, st, c, "r-shop")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := c.VerifyIDToken(ctx, tok.IDToken, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if claims.UID != "u-1" || claims.Realm != "r-shop" || claims.SID == "" || claims.Username() != "ana" {
		t.Fatalf("claims = %+v", claims)
	}
}

func TestAnIdTokenWithTheWrongNonceIsRefused(t *testing.T) {
	st := dockiotest.New(t)
	st.SignIn = &ana
	c := newClient(t, st, "acme")
	tok, _, err := signIn(t, st, c, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.VerifyIDToken(ctx, tok.IDToken, "another-nonce"); !errors.Is(err, dockio.ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

func TestAnIdTokenFromAnotherTenantIsRefused(t *testing.T) {
	st := dockiotest.New(t)
	st.SignIn = &ana
	st.IssuerOverride = st.Issuer("other") // same station, same origin, other tenant
	c := newClient(t, st, "acme")
	tok, nonce, err := signIn(t, st, c, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.VerifyIDToken(ctx, tok.IDToken, nonce); !errors.Is(err, dockio.ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

func TestATamperedIdTokenIsRefused(t *testing.T) {
	st := dockiotest.New(t)
	st.SignIn = &ana
	c := newClient(t, st, "acme")
	tok, nonce, err := signIn(t, st, c, "")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok.IDToken, ".")
	forged := st.Sign("JWT", map[string]any{"sub": "mallory"})
	parts[1] = strings.Split(forged, ".")[1]
	if _, err := c.VerifyIDToken(ctx, strings.Join(parts, "."), nonce); !errors.Is(err, dockio.ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

func TestAnExpiredSecretIsReportedAsExpiredNotWrong(t *testing.T) {
	st := dockiotest.New(t)
	c := newClient(t, st, "acme")
	st.ExpireClient(c.ClientID())
	if _, err := c.AppToken(ctx, "dockio:catalog"); !errors.Is(err, dockio.ErrSecretExpired) {
		t.Fatalf("err = %v, want ErrSecretExpired", err)
	}
}

// ---------------------------------------------------------------- notices

func TestABackchannelLogoutTokenIsAcceptedOnceOnly(t *testing.T) {
	st := dockiotest.New(t)
	c := newClient(t, st, "acme")
	tok := st.SignLogout(c.ClientID(), map[string]any{"sub": "ana", "uid": "u-1", "sid": "sid-1"})

	got, err := c.VerifyLogoutToken(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if got.UID != "u-1" || got.SID != "sid-1" {
		t.Fatalf("claims = %+v", got)
	}
	if _, err := c.VerifyLogoutToken(ctx, tok); !errors.Is(err, dockio.ErrInvalidToken) {
		t.Fatalf("replay: err = %v, want ErrInvalidToken", err)
	}
	c.ReleaseJTI(tok)
	if _, err := c.VerifyLogoutToken(ctx, tok); err != nil {
		t.Fatalf("after release: %v", err)
	}
}

func TestALogoutTokenWithANonceIsRefused(t *testing.T) {
	st := dockiotest.New(t)
	c := newClient(t, st, "acme")
	tok := st.SignLogout(c.ClientID(), map[string]any{"sub": "ana", "nonce": "n"})
	if _, err := c.VerifyLogoutToken(ctx, tok); !errors.Is(err, dockio.ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

func TestARevocationNoticeForThisClientVerifies(t *testing.T) {
	st := dockiotest.New(t)
	pkce, _ := dockio.NewPKCE()
	d, code := connectCode(t, st, pkce, returnURI)
	g, err := dockio.ExchangeConnectCode(ctx, dockio.NewHTTPClient(), d, code, pkce.Verifier, returnURI)
	if err != nil {
		t.Fatal(err)
	}
	c, err := dockio.NewClient(ctx, dockio.Config{Issuer: g.Issuer, ClientID: g.ClientID, ClientSecret: g.ClientSecret})
	if err != nil {
		t.Fatal(err)
	}

	rev, err := c.VerifyRevocation(ctx, st.SignRevocation(g.ClientID, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if rev.ConnectionID != g.ConnectionID {
		t.Fatalf("connection id = %q, want %q", rev.ConnectionID, g.ConnectionID)
	}

	// The same notice dressed as a logout token is not a revocation.
	wrongTyp := st.Sign("logout+jwt", map[string]any{"iss": g.Issuer, "aud": g.ClientID, "iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute).Unix(), "connection_id": g.ConnectionID})
	if _, err := c.VerifyRevocation(ctx, wrongTyp); !errors.Is(err, dockio.ErrInvalidToken) {
		t.Fatalf("wrong typ: err = %v, want ErrInvalidToken", err)
	}
}

// ---------------------------------------------------------------- RP API

func TestDisconnectRevokesOnceThenFindsNothing(t *testing.T) {
	st := dockiotest.New(t)
	pkce, _ := dockio.NewPKCE()
	d, code := connectCode(t, st, pkce, returnURI)
	g, _ := dockio.ExchangeConnectCode(ctx, dockio.NewHTTPClient(), d, code, pkce.Verifier, returnURI)
	c, err := dockio.NewClient(ctx, dockio.Config{Issuer: g.Issuer, ClientID: g.ClientID, ClientSecret: g.ClientSecret})
	if err != nil {
		t.Fatal(err)
	}

	revoked, err := c.Disconnect(ctx)
	if err != nil || !revoked {
		t.Fatalf("first disconnect: revoked=%v err=%v", revoked, err)
	}
	// The client is now revoked, so its credentials are refused: still "nothing
	// live to revoke", not an error.
	revoked, err = c.Disconnect(ctx)
	if err != nil || revoked {
		t.Fatalf("second disconnect: revoked=%v err=%v", revoked, err)
	}
}

func TestTheCatalogSyncsAndAnOlderVersionConflicts(t *testing.T) {
	st := dockiotest.New(t)
	c := newClient(t, st, "acme")
	cat := dockio.Catalog{Version: 3, Permissions: []dockio.Permission{{Key: "app:biz:audit:read", Name: "Read audit"}}}
	if _, err := c.SyncCatalog(ctx, cat); err != nil {
		t.Fatal(err)
	}
	if got := st.Catalog(); got == nil || got.Version != 3 {
		t.Fatalf("station catalog = %+v", got)
	}
	cat.Version = 2
	if _, err := c.SyncCatalog(ctx, cat); !errors.Is(err, dockio.ErrCatalogVersionConflict) {
		t.Fatalf("err = %v, want ErrCatalogVersionConflict", err)
	}
}

func TestEffectivePermissionsAreAskedPerRealm(t *testing.T) {
	st := dockiotest.New(t)
	st.AddPerson(ana)
	st.SetEffective("ana", "r-shop", "app:biz:audit:read")
	c := newClient(t, st, "acme")

	e, err := c.EffectiveIn(ctx, "ana", "r-shop")
	if err != nil {
		t.Fatal(err)
	}
	if e.ID != "u-1" || len(e.Keys) != 1 || e.Keys[0] != "app:biz:audit:read" {
		t.Fatalf("effective = %+v", e)
	}
	if e, _ := c.EffectiveIn(ctx, "ana", "r-elsewhere"); len(e.Keys) != 0 {
		t.Fatalf("keys leaked across realms: %+v", e)
	}
	if _, err := c.EffectiveIn(ctx, "nobody", "r-shop"); !errors.Is(err, dockio.ErrNoSuchPerson) {
		t.Fatalf("err = %v, want ErrNoSuchPerson", err)
	}
}

func TestAnUnreachableStationIsUnavailableNotInvalid(t *testing.T) {
	st := dockiotest.New(t)
	c := newClient(t, st, "acme")
	tok := st.SignLogout(c.ClientID(), map[string]any{"sub": "ana"})
	st.Close()

	// The client has never fetched the station's keys, and now cannot: that is an
	// outage, and must not read as a bad token -- or as a person without access.
	if _, err := c.VerifyLogoutToken(ctx, tok); !errors.Is(err, dockio.ErrUnavailable) {
		t.Fatalf("verify: err = %v, want ErrUnavailable", err)
	}
	if _, err := c.EffectiveIn(ctx, "ana", "r-shop"); !errors.Is(err, dockio.ErrUnavailable) {
		t.Fatalf("effective: err = %v, want ErrUnavailable", err)
	}
}
