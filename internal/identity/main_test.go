package identity

// The integration tests run against a REAL Postgres, because what they check IS
// the SQL -- organization isolation, the append-only trigger, the single-use
// attempts -- and against an in-process fake døckio (internal/dockio/dockiotest),
// because what they check is also the protocol.
//
// Without TEST_POSTGRES_DSN they skip, so `go test ./...` works on a laptop with
// no database.

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/miguelrosalesmtl/go-dockio-template/internal/database"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/dockio"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/dockio/dockiotest"
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

// suiteLockKey serialises the packages that share the test database: go test
// runs packages in parallel, and each one wipes the tables it uses.
const suiteLockKey = 918273645

func lockSuite(dsn string) func() {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lock suite: %v\n", err)
		os.Exit(1)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`SELECT pg_advisory_lock($1)`, suiteLockKey); err != nil {
		fmt.Fprintf(os.Stderr, "lock suite: %v\n", err)
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

// ---------------------------------------------------------------- fixtures

const (
	testPublicURL = "http://127.0.0.1:1" // never dialled: døckio only redirects to it
	testAppKey    = "app"
	testPassword  = "correct-horse-battery-staple"
)

// env is one test's world: a clean database, a fake døckio, and a Service.
type env struct {
	t       *testing.T
	ctx     context.Context
	svc     *Service
	station *dockiotest.Station
	admin   User // a local superuser
}

func newEnv(t *testing.T) *env {
	t.Helper()
	if testPool == nil {
		t.Skip("set TEST_POSTGRES_DSN to run integration tests (or run `make test-integration`)")
	}
	cleanDatabase(t)

	key := make([]byte, secrets.KeySize)
	_, _ = rand.Read(key)
	box, err := secrets.New(key)
	if err != nil {
		t.Fatal(err)
	}
	st := dockiotest.New(t)
	svc := NewService(testPool, Config{
		Auth: settings.Auth{SessionTTL: time.Hour, MinPasswordLength: 16, ArgonMemoryKiB: 64, ArgonIterations: 1, ArgonParallelism: 1},
		Dockio: settings.Dockio{
			PublicURL: testPublicURL, StationURL: st.URL, AppName: "Test", AppKey: testAppKey,
			HomeRealm: "app", Needs: []string{"spanning"}, MaxExpiryDays: 365, PermissionCacheTTL: time.Minute,
		},
		Frontend: settings.Frontend{BaseURL: "http://127.0.0.1:2", LoginPath: "/login", SigninSettingsPath: "/system/sign-in"},
		Secrets:  box,
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	ctx := context.Background()
	if err := svc.SyncPermissions(ctx); err != nil {
		t.Fatal(err)
	}
	admin, _, err := svc.CreateSuperuser(ctx, "root@example.com", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, ctx: ctx, svc: svc, station: st, admin: admin}
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

// browse performs one browser hop without following the redirect and returns
// the query of the Location the browser was sent to.
func browse(t *testing.T, rawURL string) url.Values {
	t.Helper()
	resp, err := dockio.NewHTTPClient().Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET %s: %d, want 302", rawURL, resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc.Query()
}

// connect runs Quick connect end to end as actor and returns the result.
func (e *env) connect(actor User, renew bool) (ConnectResult, error) {
	e.t.Helper()
	redirect, state, err := e.svc.StartConnect(e.ctx, actor, "", renew)
	if err != nil {
		e.t.Fatalf("start connect: %v", err)
	}
	q := browse(e.t, redirect)
	return e.svc.CompleteConnect(e.ctx, state, q.Get("state"), q.Get("code"), q.Get("error"))
}

// connected connects and turns sign-in on: the state most tests start from.
func (e *env) connected() ConnectionSettings {
	e.t.Helper()
	if _, err := e.connect(e.admin, false); err != nil {
		e.t.Fatalf("connect: %v", err)
	}
	if err := e.svc.SetSigninEnabled(e.ctx, e.admin, true); err != nil {
		e.t.Fatalf("enable sign-in: %v", err)
	}
	c, err := e.svc.repo.GetConnection(e.ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

// signIn runs a døckio sign-in for whoever the station has as SignIn.
func (e *env) signIn(orgSlug string) (SignInResult, error) {
	e.t.Helper()
	redirect, state, err := e.svc.StartSignIn(e.ctx, orgSlug, "/dashboard")
	if err != nil {
		return SignInResult{}, err
	}
	q := browse(e.t, redirect)
	return e.svc.CompleteSignIn(e.ctx, state, q.Get("state"), q.Get("code"), q.Get("error"), RequestMeta{IPAddress: "203.0.113.9"})
}

// session authenticates a sign-in's token.
func (e *env) session(token string) (User, Session) {
	e.t.Helper()
	u, s, err := e.svc.Authenticate(e.ctx, token)
	if err != nil {
		e.t.Fatalf("authenticate: %v", err)
	}
	return u, s
}

// wire is a permission as døckio knows it.
func wire(p Permission) string { return p.WireKey(testAppKey) }

func flowCode(err error) string {
	var fe *FlowError
	if errors.As(err, &fe) {
		return fe.Code
	}
	return ""
}

func countAudit(t *testing.T, action string) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action = $1`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
