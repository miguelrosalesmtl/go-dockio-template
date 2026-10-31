package server

// HTTP-level tests: the real router, the real middleware, a real Postgres, and a
// fake døckio (internal/dockio/dockiotest). They drive the browser round trips
// the way a browser would -- following redirects by hand and carrying cookies --
// so what they prove is the wiring: which routes are public, which cookie goes
// where, what the front end is redirected to.

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/miguelrosalesmtl/go-dockio-template/internal/database"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/dockio"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/dockio/dockiotest"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/identity"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/secrets"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/settings"
	"github.com/miguelrosalesmtl/go-dockio-template/migrations"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		os.Exit(m.Run())
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err == nil {
		err = pool.Ping(ctx)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "TEST_POSTGRES_DSN: %v\n", err)
		os.Exit(1)
	}
	testPool = pool
	unlock := lockSuite(dsn)
	if err := applyMigrations(dsn); err != nil {
		unlock()
		fmt.Fprintf(os.Stderr, "apply migrations: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	unlock()
	pool.Close()
	os.Exit(code)
}

const suiteLockKey = 918273645

func lockSuite(dsn string) func() {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		os.Exit(1)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`SELECT pg_advisory_lock($1)`, suiteLockKey); err != nil {
		os.Exit(1)
	}
	return func() {
		_, _ = db.Exec(`SELECT pg_advisory_unlock($1)`, suiteLockKey)
		_ = db.Close()
	}
}

func applyMigrations(dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.Up(db, ".")
}

func cleanDatabase(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	err := database.InTx(ctx, testPool, func(db database.DB) error {
		if _, err := db.Exec(ctx, `SET LOCAL app.audit_purge = 'on'`); err != nil {
			return err
		}
		for _, stmt := range []string{
			`DELETE FROM audit_log`, `DELETE FROM oidc_login_attempts`, `DELETE FROM oidc_connect_attempts`,
			`DELETE FROM oidc_settings`, `DELETE FROM api_keys`, `DELETE FROM sessions`,
			`DELETE FROM oidc_identities`, `DELETE FROM organizations`, `DELETE FROM users`,
		} {
			if _, err := db.Exec(ctx, stmt); err != nil {
				return fmt.Errorf("%s: %w", stmt, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("clean database: %v", err)
	}
}

// ---------------------------------------------------------------- harness

const (
	testOrigin     = "https://app.example.com"
	testPublicURL  = "http://127.0.0.1:1"
	testFrontend   = "http://127.0.0.1:2"
	testPassword   = "correct-horse-battery-staple"
	testAdminEmail = "root@example.com"
	testAppKey     = "app"
)

type harness struct {
	t       *testing.T
	ctx     context.Context
	svc     *identity.Service
	handler http.Handler
	station *dockiotest.Station
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	if testPool == nil {
		t.Skip("set TEST_POSTGRES_DSN to run integration tests (or run `make test-integration`)")
	}
	cleanDatabase(t)

	key := make([]byte, secrets.KeySize)
	_, _ = rand.Read(key)
	box, _ := secrets.New(key)
	st := dockiotest.New(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	auth := settings.Auth{
		SessionTTL: time.Hour, SessionCookieName: "session", SessionCookieSecure: false,
		MinPasswordLength: 16, ArgonMemoryKiB: 64, ArgonIterations: 1, ArgonParallelism: 1,
	}
	frontend := settings.Frontend{BaseURL: testFrontend, LoginPath: "/login", SigninSettingsPath: "/system/sign-in"}
	svc := identity.NewService(testPool, identity.Config{
		Auth: auth, Frontend: frontend, Secrets: box, Log: log,
		Dockio: settings.Dockio{
			PublicURL: testPublicURL, StationURL: st.URL, AppName: "Test", AppKey: testAppKey, HomeRealm: "app",
			Needs: []string{"spanning", "provisioning"}, MaxExpiryDays: 365, PermissionCacheTTL: time.Minute,
		},
	})
	ctx := context.Background()
	if err := svc.SyncPermissions(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.CreateSuperuser(ctx, testAdminEmail, testPassword); err != nil {
		t.Fatal(err)
	}
	srv := New(Config{
		CORS: settings.CORS{AllowedOrigins: []string{testOrigin}}, Auth: auth, Frontend: frontend,
		Debug: true, Identity: svc, Pool: testPool, Log: log,
	})
	t.Cleanup(func() { close(srv.done) })
	return &harness{t: t, ctx: ctx, svc: svc, handler: srv.routes(), station: st}
}

// browser is a cookie jar driving the API the way a browser would.
type browser struct {
	h       *harness
	cookies map[string]*http.Cookie
}

func (h *harness) browser() *browser { return &browser{h: h, cookies: map[string]*http.Cookie{}} }

// do sends a request with the jar's cookies and stores whatever it sets. body
// may be nil, a string (sent as is), or anything JSON-encodable.
func (b *browser) do(method, target string, body any, headers ...string) *httptest.ResponseRecorder {
	b.h.t.Helper()
	var reader io.Reader
	switch v := body.(type) {
	case nil:
	case string:
		reader = strings.NewReader(v)
	default:
		raw, _ := json.Marshal(v)
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, target, reader)
	if _, ok := body.(string); !ok && body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	for _, c := range b.cookies {
		if strings.HasPrefix(req.URL.Path, c.Path) {
			req.AddCookie(c)
		}
	}
	rec := httptest.NewRecorder()
	b.h.handler.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return rec
}

// location returns a redirect's target, failing unless the answer is a 302.
func location(t *testing.T, rec *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d, want 302; body: %s", rec.Code, rec.Body.String())
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// atDockio performs the browser's visit to døckio and returns where døckio sent
// it back to, as a path and query on this API.
func atDockio(t *testing.T, rawURL string) string {
	t.Helper()
	resp, err := dockio.NewHTTPClient().Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	back, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || !strings.HasPrefix(back.String(), testPublicURL) {
		t.Fatalf("døckio sent the browser to %q", resp.Header.Get("Location"))
	}
	return back.RequestURI()
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return v
}

// adminBrowser is signed in as the local superuser through the emergency page.
func (h *harness) adminBrowser() *browser {
	h.t.Helper()
	b := h.browser()
	rec := b.do("POST", "/api/v1/auth/admin-login", map[string]string{"email": testAdminEmail, "password": testPassword})
	if rec.Code != http.StatusOK || b.cookies["session"] == nil {
		h.t.Fatalf("admin login: %d %s", rec.Code, rec.Body.String())
	}
	return b
}

// csrf is the header a front end sends on every state-changing request.
var csrf = []string{"X-CSRF-Protection", "1"}

// connectOverHTTP runs Quick connect through the API as b, and turns sign-in on.
func (h *harness) connectOverHTTP(b *browser) {
	h.t.Helper()
	rec := b.do("POST", "/api/v1/system/signin/connect", map[string]any{}, csrf...)
	if rec.Code != http.StatusOK {
		h.t.Fatalf("connect start: %d %s", rec.Code, rec.Body.String())
	}
	back := atDockio(h.t, decode[map[string]string](h.t, rec)["redirect_url"])
	if got := location(h.t, b.do("GET", back, nil)); got.Query().Get("connected") != "1" {
		h.t.Fatalf("connect callback went to %s", got)
	}
	if rec := b.do("PATCH", "/api/v1/system/signin", map[string]bool{"enabled": true}, csrf...); rec.Code != http.StatusOK {
		h.t.Fatalf("enable sign-in: %d %s", rec.Code, rec.Body.String())
	}
}

// signInOverHTTP signs whoever the station has as SignIn in, through the API.
func (h *harness) signInOverHTTP(query string) (*browser, *url.URL) {
	h.t.Helper()
	b := h.browser()
	start := location(h.t, b.do("GET", "/api/v1/auth/oidc/login"+query, nil))
	if !strings.HasPrefix(start.String(), h.station.URL) {
		return b, start // refused before døckio: the front end's login page
	}
	return b, location(h.t, b.do("GET", atDockio(h.t, start.String()), nil))
}

func authCfg() settings.Auth {
	return settings.Auth{
		SessionTTL: time.Hour, SessionCookieName: "session", MinPasswordLength: 16,
		ArgonMemoryKiB: 64, ArgonIterations: 1, ArgonParallelism: 1,
	}
}

func frontendCfg() settings.Frontend {
	return settings.Frontend{BaseURL: testFrontend, LoginPath: "/login", SigninSettingsPath: "/system/sign-in"}
}

func settingsRateLimit(attempts int) settings.RateLimit {
	return settings.RateLimit{Enabled: true, Attempts: attempts, Window: time.Minute}
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
