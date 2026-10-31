package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/miguelrosalesmtl/go-dockio-template/internal/dockio/dockiotest"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/identity"
)

var ana = dockiotest.Person{UID: "u-ana", Username: "ana", Email: "ana@example.com", GivenName: "Ana", Realms: []string{"r-shop"}}

func TestTheManifestNamesOurURIsOnOurOrigin(t *testing.T) {
	h := newHarness(t)
	m := decode[map[string]any](t, h.browser().do("GET", "/api/v1/dockio/manifest", nil))
	if m["dockio_manifest"] != "1" || m["app_key"] != testAppKey || m["home_realm"] != "app" {
		t.Fatalf("manifest = %v", m)
	}
	for _, k := range []string{"revocation_uri", "backchannel_logout_uri"} {
		if !strings.HasPrefix(m[k].(string), testPublicURL+"/api/v1/") {
			t.Fatalf("%s = %v", k, m[k])
		}
	}
}

func TestBeforeAnyConnectionSignInIsUnavailableAndSaysSo(t *testing.T) {
	h := newHarness(t)
	b := h.browser()
	if cfg := decode[map[string]bool](t, b.do("GET", "/api/v1/auth/config", nil)); cfg["signin_available"] {
		t.Fatal("sign-in claims to be available with no connection")
	}
	to := location(t, b.do("GET", "/api/v1/auth/oidc/login", nil))
	if to.Path != "/login" || to.Query().Get("error") != identity.CodeSigninUnavailable {
		t.Fatalf("redirected to %s", to)
	}
}

func TestTheWholeFlowOverHTTP(t *testing.T) {
	h := newHarness(t)
	admin := h.adminBrowser()
	h.connectOverHTTP(admin)

	rec := admin.do("POST", "/api/v1/system/organizations",
		map[string]string{"slug": "shop", "name": "Shop", "dockio_realm": "r-shop"}, csrf...)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create organization: %d %s", rec.Code, rec.Body.String())
	}

	h.station.AddPerson(ana)
	h.station.SignIn = &ana
	h.station.SetEffective("ana", "r-shop", "app:biz:organization:read", "app:biz:apikeys:create")

	// Ana signs in from her business's own page.
	ana, landed := h.signInOverHTTP("?organization=shop&return_to=/orders")
	if landed.String() != testFrontend+"/orders" || ana.cookies["session"] == nil {
		t.Fatalf("landed on %s, cookie %v", landed, ana.cookies["session"])
	}
	if ana.cookies["session"].SameSite != http.SameSiteLaxMode || !ana.cookies["session"].HttpOnly {
		t.Fatal("the session cookie is not HttpOnly and SameSite=Lax")
	}

	me := decode[map[string]any](t, ana.do("GET", "/api/v1/auth/me", nil))
	if me["auth_method"] != "dockio" {
		t.Fatalf("me = %v", me)
	}
	orgs := decode[map[string][]map[string]any](t, ana.do("GET", "/api/v1/organizations", nil))
	if len(orgs["organizations"]) != 1 || orgs["organizations"][0]["slug"] != "shop" {
		t.Fatalf("organizations = %v", orgs)
	}
	if rec := ana.do("GET", "/api/v1/organizations/shop/", nil); rec.Code != http.StatusOK {
		t.Fatalf("get organization: %d %s", rec.Code, rec.Body.String())
	}
	// døckio grants her no organization.update.
	if rec := ana.do("PATCH", "/api/v1/organizations/shop/", map[string]string{"name": "X"}, csrf...); rec.Code != http.StatusForbidden {
		t.Fatalf("rename without the permission: %d", rec.Code)
	}
	// And no system permission: the system surface does not exist for her.
	if rec := ana.do("GET", "/api/v1/system/signin/", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("system surface: %d, want 404", rec.Code)
	}

	// She signs out; the answer points at døckio's end-session endpoint.
	out := decode[map[string]string](t, ana.do("POST", "/api/v1/auth/logout", nil, csrf...))
	if !strings.HasPrefix(out["logout_url"], h.station.URL+"/end-session?") {
		t.Fatalf("logout url = %q", out["logout_url"])
	}
	if rec := ana.do("GET", "/api/v1/auth/me", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after sign-out: %d", rec.Code)
	}
}

func TestACookieAloneCannotChangeAnything(t *testing.T) {
	h := newHarness(t)
	admin := h.adminBrowser()
	if rec := admin.do("PATCH", "/api/v1/system/signin", map[string]bool{"enabled": true}); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), "X-CSRF-Protection") {
		t.Fatalf("no CSRF header: %d %s", rec.Code, rec.Body.String())
	}
	// A bearer token is not sent by the browser on its own: no header needed.
	token := decode[map[string]any](t, h.browser().do("POST", "/api/v1/auth/admin-login",
		map[string]string{"email": testAdminEmail, "password": testPassword}))["token"].(string)
	rec := h.browser().do("POST", "/api/v1/system/organizations",
		map[string]string{"slug": "shop", "name": "Shop"}, "Authorization", "Bearer "+token)
	if rec.Code != http.StatusCreated {
		t.Fatalf("bearer without CSRF header: %d %s", rec.Code, rec.Body.String())
	}
}

func TestAConnectCallbackFromAnotherBrowserIsRefused(t *testing.T) {
	h := newHarness(t)
	admin := h.adminBrowser()
	rec := admin.do("POST", "/api/v1/system/signin/connect", map[string]any{}, csrf...)
	back := atDockio(t, decode[map[string]string](t, rec)["redirect_url"])

	// An attacker who got hold of the callback URL replays it in their browser.
	to := location(t, h.browser().do("GET", back, nil))
	if to.Path != "/system/sign-in" || to.Query().Get("connect_error") != identity.CodeInvalidState {
		t.Fatalf("redirected to %s", to)
	}
	// The secret never reaches any URL, success or failure.
	if strings.Contains(to.String(), "sec_") {
		t.Fatal("a secret leaked into a redirect")
	}
}

func TestRevocationNoticeOverHTTP(t *testing.T) {
	h := newHarness(t)
	h.connectOverHTTP(h.adminBrowser())
	conn, _ := h.svc.Connection(h.ctx)

	post := func(token string) int {
		return h.browser().do("POST", "/api/v1/dockio/connection-revoked", url.Values{"token": {token}}.Encode(),
			"Content-Type", "application/x-www-form-urlencoded").Code
	}
	if code := post("garbage"); code != http.StatusBadRequest {
		t.Fatalf("garbage: %d", code)
	}
	notice := h.station.SignRevocation(conn.ClientID, time.Now().Add(time.Second))
	if code := post(notice); code != http.StatusNoContent {
		t.Fatalf("valid notice: %d", code)
	}
	if code := post(notice); code != http.StatusNoContent {
		t.Fatalf("repeat: %d, want 204 so døckio stops retrying", code)
	}
	if cfg := decode[map[string]bool](t, h.browser().do("GET", "/api/v1/auth/config", nil)); !cfg["unavailable"] {
		t.Fatal("the login page is not told sign-in is unavailable")
	}
}

func TestTheEmergencySignInIsRateLimited(t *testing.T) {
	h := newHarness(t)
	srv := New(Config{
		RateLimit: settingsRateLimit(3), Auth: authCfg(), Frontend: frontendCfg(),
		Identity: h.svc, Pool: testPool, Log: discard(),
	})
	defer close(srv.done)
	handler := srv.routes()
	var last int
	for i := 0; i < 5; i++ {
		b := &browser{h: &harness{t: t, handler: handler}, cookies: map[string]*http.Cookie{}}
		last = b.do("POST", "/api/v1/auth/admin-login", map[string]string{"email": testAdminEmail, "password": "wrong-password-xx"}).Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("status after 5 attempts = %d, want 429", last)
	}
}

func TestAPIKeysWorkOnlyOnTheirOrganization(t *testing.T) {
	h := newHarness(t)
	admin := h.adminBrowser()
	for _, slug := range []string{"shop", "bakery"} {
		admin.do("POST", "/api/v1/system/organizations", map[string]string{"slug": slug, "name": slug}, csrf...)
	}
	rec := admin.do("POST", "/api/v1/organizations/shop/api-keys",
		map[string]any{"name": "reports", "permissions": []string{"audit.read"}}, csrf...)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create key: %d %s", rec.Code, rec.Body.String())
	}
	key := decode[map[string]any](t, rec)["token"].(string)
	bearer := []string{"Authorization", "Bearer " + key}

	if rec := h.browser().do("GET", "/api/v1/organizations/shop/audit", nil, bearer...); rec.Code != http.StatusOK {
		t.Fatalf("own organization: %d", rec.Code)
	}
	if rec := h.browser().do("GET", "/api/v1/organizations/bakery/audit", nil, bearer...); rec.Code != http.StatusNotFound {
		t.Fatalf("another organization: %d, want 404", rec.Code)
	}
	if rec := h.browser().do("GET", "/api/v1/organizations/shop/api-keys", nil, bearer...); rec.Code != http.StatusForbidden {
		t.Fatalf("outside its scope: %d, want 403", rec.Code)
	}
	if rec := h.browser().do("GET", "/api/v1/auth/me", nil, bearer...); rec.Code != http.StatusForbidden {
		t.Fatalf("account routes with a key: %d, want 403", rec.Code)
	}
}

func TestTheSuperuserBypassIsAudited(t *testing.T) {
	h := newHarness(t)
	admin := h.adminBrowser()
	admin.do("POST", "/api/v1/system/organizations", map[string]string{"slug": "shop", "name": "Shop"}, csrf...)
	if rec := admin.do("GET", "/api/v1/organizations/shop/", nil); rec.Code != http.StatusOK {
		t.Fatalf("superuser into shop: %d", rec.Code)
	}
	var n int
	_ = testPool.QueryRow(h.ctx, `SELECT count(*) FROM audit_log WHERE action = 'superuser.organization_accessed'`).Scan(&n)
	if n != 1 {
		t.Fatalf("bypass audit entries = %d, want 1", n)
	}
}

func TestSecurityHeadersAndCORS(t *testing.T) {
	h := newHarness(t)
	rec := h.browser().do("OPTIONS", "/api/v1/auth/me", nil, "Origin", testOrigin, "Access-Control-Request-Method", "PATCH")
	if !strings.Contains(rec.Header().Get("Access-Control-Allow-Headers"), "X-CSRF-Protection") {
		t.Fatalf("preflight does not allow the CSRF header: %v", rec.Header())
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != testOrigin {
		t.Fatal("an allowlisted origin was not echoed")
	}
	rec = h.browser().do("GET", "/healthz", nil, "Origin", "https://evil.example")
	if rec.Header().Get("Access-Control-Allow-Origin") != "" || rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("headers = %v", rec.Header())
	}
}
