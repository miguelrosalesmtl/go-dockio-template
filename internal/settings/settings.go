// Package settings loads and holds all application configuration.
//
// It works like Django's settings module: a single, typed, immutable object
// that is populated once at startup from environment variables (optionally
// seeded from a .env file) and then passed explicitly to the components that
// need it. Nothing else in the codebase should read os.Getenv directly.
package settings

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

// Settings is the fully-resolved configuration for a single process.
type Settings struct {
	App          App
	Server       Server
	Postgres     Postgres
	Auth         Auth
	Audit        Audit
	Organization Organization
	CORS         CORS
	RateLimit    RateLimit
	Dockio       Dockio
	Frontend     Frontend
	Secrets      Secrets
}

// RateLimit configures the limiter on the public endpoints.
//
// It is IN-MEMORY and therefore PER-REPLICA: three replicas means three times the
// configured allowance. That is a deliberate trade -- the alternative is a shared
// counter, which means Redis, which this template does not have.
//
// It is a speed bump, not a wall. A serious deployment puts the real limiter at
// the proxy or the WAF, where it can see every replica's traffic and drop the
// request before it costs you a goroutine. This one exists so that an unprotected
// deployment is not trivially brute-forceable.
type RateLimit struct {
	// Enabled turns the limiter off entirely. Useful in tests.
	Enabled bool `env:"RATE_LIMIT_ENABLED" envDefault:"true"`
	// Attempts is how many requests one key may make per Window.
	Attempts int `env:"RATE_LIMIT_ATTEMPTS" envDefault:"10"`
	// Window is the period over which Attempts are counted.
	Window time.Duration `env:"RATE_LIMIT_WINDOW" envDefault:"1m"`
}

// Audit holds the audit log's retention policy.
type Audit struct {
	// Retention is how long audit entries are kept. ZERO -- THE DEFAULT -- MEANS
	// KEEP FOREVER.
	//
	// The default is deliberate. Quietly destroying somebody's compliance evidence
	// because a config value defaulted to 90 days is not a decision this template
	// will make on your behalf. Set it, once you know what your obligations are:
	// most regimes want years, and "forever" is a real answer too, right up until
	// a right-to-erasure request arrives.
	//
	// The purge is the ONLY thing permitted to delete from audit_log; the database
	// trigger refuses everything else.
	Retention time.Duration `env:"AUDIT_RETENTION" envDefault:"0"`
}

// Organization holds the organization lifecycle policy.
type Organization struct {
	// Retention is how long a SOFT-DELETED organization is kept before it is destroyed
	// for real, cascading away every row it owns. ZERO -- THE DEFAULT -- MEANS KEEP
	// FOREVER.
	//
	// This is your right-to-erasure mechanism, and it is the only thing in the
	// application that permanently destroys organization data. It is off by default for
	// the same reason AUDIT_RETENTION is: silently shredding a customer's data
	// because a config value had a tidy default is not a decision this template
	// makes for you. 30d is a common choice, and gives support time to undo an
	// accident.
	Retention time.Duration `env:"ORGANIZATION_RETENTION" envDefault:"0"`
}

// CORS controls which browser origins may call this API.
type CORS struct {
	// AllowedOrigins is an explicit allowlist, e.g.
	// "https://app.example.com,https://admin.example.com".
	//
	// Empty means CORS is OFF and no browser on another origin can call the API,
	// which is the correct default for an API with no browser client.
	//
	// A "*" wildcard is REFUSED at startup in production. The API authenticates
	// with a session cookie or a bearer token, and a wildcard origin that also
	// allows credentials is precisely the configuration the CORS spec forbids --
	// every site on the internet could make authenticated calls as your users.
	AllowedOrigins []string `env:"CORS_ALLOWED_ORIGINS" envSeparator:","`
}

// App holds top-level, environment-wide options.
type App struct {
	// Environment is one of "development", "staging", "production".
	Environment string `env:"APP_ENV" envDefault:"development"`
	// Debug enables human-readable logs and developer-friendly error output.
	// It must be false in production: it is what decides whether internal error
	// messages are echoed back to the caller.
	Debug bool `env:"APP_DEBUG" envDefault:"true"`
	// LogLevel is one of "debug", "info", "warn", "error".
	LogLevel string `env:"LOG_LEVEL" envDefault:"info"`
	// InstanceID uniquely identifies this replica. In Kubernetes this is
	// typically injected from metadata.name via the downward API; it tags every
	// log line so you can tell replicas apart in aggregated logs.
	InstanceID string `env:"INSTANCE_ID" envDefault:""`
}

// Server holds HTTP server configuration.
type Server struct {
	Host            string        `env:"SERVER_HOST" envDefault:"0.0.0.0"`
	Port            int           `env:"SERVER_PORT" envDefault:"8080"`
	ReadTimeout     time.Duration `env:"SERVER_READ_TIMEOUT" envDefault:"10s"`
	WriteTimeout    time.Duration `env:"SERVER_WRITE_TIMEOUT" envDefault:"10s"`
	IdleTimeout     time.Duration `env:"SERVER_IDLE_TIMEOUT" envDefault:"60s"`
	ShutdownTimeout time.Duration `env:"SERVER_SHUTDOWN_TIMEOUT" envDefault:"15s"`
	// TrustProxyHeaders makes the server believe X-Forwarded-For when recording
	// a client IP. Enable it only when the app really does sit behind a proxy
	// or load balancer that overwrites the header, otherwise a caller can forge
	// the IP that lands in your session and audit records.
	TrustProxyHeaders bool `env:"SERVER_TRUST_PROXY_HEADERS" envDefault:"false"`
}

// Addr returns the host:port the HTTP server should bind to.
func (s Server) Addr() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

// Postgres holds the connection settings for the database, which is the only
// source of truth in this template: there is no cache tier to invalidate.
type Postgres struct {
	Host string `env:"POSTGRES_HOST" envDefault:"localhost"`
	Port int    `env:"POSTGRES_PORT" envDefault:"5432"`
	// ONE user, owning ONE database -- the app's own. The app never connects as the
	// cluster superuser and never touches another database.
	//
	// Note what this design does NOT give you: a tamper-proof audit log. A user with
	// full rights over the database can delete from audit_log, and the append-only
	// trigger cannot stop it (any role may set the GUC the trigger checks). See the
	// audit package. That was a deliberate trade for operational simplicity.
	User            string        `env:"POSTGRES_USER" envDefault:"app"`
	Password        string        `env:"POSTGRES_PASSWORD" envDefault:"app"`
	Database        string        `env:"POSTGRES_DB" envDefault:"app"`
	SSLMode         string        `env:"POSTGRES_SSLMODE" envDefault:"disable"`
	MaxConns        int32         `env:"POSTGRES_MAX_CONNS" envDefault:"10"`
	MinConns        int32         `env:"POSTGRES_MIN_CONNS" envDefault:"2"`
	MaxConnLifetime time.Duration `env:"POSTGRES_MAX_CONN_LIFETIME" envDefault:"1h"`
	MaxConnIdleTime time.Duration `env:"POSTGRES_MAX_CONN_IDLE_TIME" envDefault:"30m"`
}

// DSN returns a libpq-style connection string.
func (p Postgres) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		p.Host, p.Port, p.User, p.Password, p.Database, p.SSLMode,
	)
}

// Auth holds the knobs for sessions and for the local superuser's password.
//
// There is no invitation, password-reset or email-verification setting here:
// døckio owns all of that. The only password in the system belongs to the local
// break-glass superuser.
type Auth struct {
	// SessionTTL is how long a session stays valid after sign-in.
	SessionTTL time.Duration `env:"AUTH_SESSION_TTL" envDefault:"720h"` // 30 days

	// SessionCookieName is the cookie a browser session rides in. The browser
	// never holds a døckio token: the server keeps those, and the cookie only
	// names a server-side session.
	SessionCookieName string `env:"AUTH_SESSION_COOKIE_NAME" envDefault:"session"`
	// SessionCookieSecure marks the cookie Secure. It may be false only outside
	// production, for plain-http local development.
	SessionCookieSecure bool `env:"AUTH_SESSION_COOKIE_SECURE" envDefault:"true"`

	// MinPasswordLength applies to the local superuser's password.
	MinPasswordLength int `env:"AUTH_MIN_PASSWORD_LENGTH" envDefault:"16"`

	// Argon2id parameters. The defaults are OWASP's recommended second option
	// (19 MiB memory, 2 iterations, 1 degree of parallelism). Never lower them to
	// make tests faster; lower them in the test itself.
	ArgonMemoryKiB   uint32 `env:"AUTH_ARGON_MEMORY_KIB" envDefault:"19456"`
	ArgonIterations  uint32 `env:"AUTH_ARGON_ITERATIONS" envDefault:"2"`
	ArgonParallelism uint8  `env:"AUTH_ARGON_PARALLELISM" envDefault:"1"`
}

// Dockio describes this application to døckio. Nothing here is a credential:
// the client id and secret come from Quick connect (or manual setup) and live,
// sealed, in the database -- see docs/dockio.md.
type Dockio struct {
	// PublicURL is this API's public origin. døckio fetches the manifest from it
	// and every URI the manifest lists is built on it, so it must be reachable
	// from døckio and, outside local development, https.
	PublicURL string `env:"APP_PUBLIC_URL" envDefault:"http://localhost:8080"`
	// StationURL is the døckio station Quick connect defaults to.
	StationURL string `env:"DOCKIO_STATION_URL" envDefault:"https://døck.io"`

	// AppName and LogoURI are what døckio shows the operator who approves the
	// connection, and the people who sign in.
	AppName string `env:"DOCKIO_APP_NAME" envDefault:"My App"`
	LogoURI string `env:"DOCKIO_LOGO_URI" envDefault:""`
	// AppKey is the application's permission namespace in døckio. Every key in
	// the catalog is published as "<AppKey>:biz:..." or "<AppKey>:system:...".
	AppKey string `env:"DOCKIO_APP_KEY" envDefault:"app"`
	// HomeRealm is the realm a new connection's client lives in: the operator's
	// own staff realm, where system permissions are granted.
	HomeRealm string `env:"DOCKIO_HOME_REALM" envDefault:"app"`
	// Needs lists the døckio switches the application uses: spanning (a realm
	// per customer), provisioning (creating realms and apps), first_party.
	Needs []string `env:"DOCKIO_NEEDS" envSeparator:"," envDefault:"spanning,provisioning"`
	// MaxExpiryDays caps the connection lifetime an operator can pick.
	MaxExpiryDays int `env:"DOCKIO_MAX_EXPIRY_DAYS" envDefault:"365"`

	// PermissionCacheTTL is how long døckio's answer to "what may this person do
	// in this organization" is reused. When døckio cannot be reached, the last
	// answer is used for at most this long; after that requests are refused.
	PermissionCacheTTL time.Duration `env:"DOCKIO_PERMISSION_CACHE_TTL" envDefault:"60s"`
}

// Frontend names the single-page app's routes this API redirects the browser to.
// They are paths on APP_BASE_URL.
type Frontend struct {
	// BaseURL is the public origin of the front end. It may equal APP_PUBLIC_URL.
	BaseURL string `env:"APP_BASE_URL" envDefault:"http://localhost:8080"`
	// LoginPath receives ?error=<code> when sign-in fails, and ?signed_out=1.
	LoginPath string `env:"FRONTEND_LOGIN_PATH" envDefault:"/login"`
	// SigninSettingsPath is the page where an operator manages the døckio
	// connection; it receives ?connected=1, ?renewed=1 or ?connect_error=<code>.
	SigninSettingsPath string `env:"FRONTEND_SIGNIN_SETTINGS_PATH" envDefault:"/system/sign-in"`
}

// URL joins BaseURL and path.
func (f Frontend) URL(path string) string {
	return strings.TrimRight(f.BaseURL, "/") + path
}

// DevSecretsKey is the key in .env.example. It is refused in production.
const DevSecretsKey = "ZGV2LW9ubHktZGV2LW9ubHktZGV2LW9ubHktZGV2LTA=" //nolint:gosec // public on purpose; refused in production

// Secrets holds the key that seals values the server must read back: the døckio
// client secret, PKCE verifiers, stored id tokens.
type Secrets struct {
	// Key is base64 of 32 random bytes: `openssl rand -base64 32`. Losing it
	// loses the sealed values -- the connection then has to be made again -- so
	// store it like any other production secret.
	Key string `env:"SECRETS_KEY,required,unset"`
}

// Load reads the .env file (if present) and parses environment variables into
// a Settings value. A missing .env file is not an error -- in production the
// configuration comes from real environment variables, ConfigMaps, and Secrets.
func Load() (*Settings, error) {
	// Best-effort: load .env if it exists. Real environment variables always win,
	// because godotenv does not overwrite variables that are already set.
	_ = godotenv.Load()

	var s Settings
	if err := env.Parse(&s); err != nil {
		return nil, fmt.Errorf("settings: parse environment: %w", err)
	}

	if err := s.validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// IsProduction reports whether the app is running in a production environment.
func (s *Settings) IsProduction() bool {
	return s.App.Environment == "production"
}

// validate rejects configurations that would be unsafe or nonsensical, at
// startup, rather than letting them fail later under load.
func (s *Settings) validate() error {
	if s.Server.Port <= 0 || s.Server.Port > 65535 {
		return fmt.Errorf("settings: invalid SERVER_PORT %d", s.Server.Port)
	}
	if s.Postgres.MinConns > s.Postgres.MaxConns {
		return fmt.Errorf(
			"settings: POSTGRES_MIN_CONNS (%d) exceeds POSTGRES_MAX_CONNS (%d)",
			s.Postgres.MinConns, s.Postgres.MaxConns,
		)
	}
	// A zero TTL is not "no expiry" -- it makes expires_at equal now(), so every
	// token is expired the instant it is minted, and the user gets a link that
	// silently never works. Refuse all three rather than ship that.
	if s.Auth.SessionTTL <= 0 {
		return fmt.Errorf("settings: AUTH_SESSION_TTL must be positive")
	}
	if s.Auth.MinPasswordLength < 12 {
		return fmt.Errorf("settings: AUTH_MIN_PASSWORD_LENGTH must be at least 12 -- it guards the one account that bypasses døckio")
	}
	if s.Auth.SessionCookieName == "" {
		return fmt.Errorf("settings: AUTH_SESSION_COOKIE_NAME must not be empty")
	}
	if s.IsProduction() && !s.Auth.SessionCookieSecure {
		return fmt.Errorf("settings: AUTH_SESSION_COOKIE_SECURE must be true in production")
	}
	if s.Auth.ArgonParallelism == 0 {
		return fmt.Errorf("settings: AUTH_ARGON_PARALLELISM must be at least 1")
	}
	// Debug mode leaks internal error strings to callers, so it must never be on
	// in production even if someone sets it there by accident.
	if s.IsProduction() && s.App.Debug {
		return fmt.Errorf("settings: APP_DEBUG must be false when APP_ENV=production")
	}
	if s.IsProduction() && s.Postgres.SSLMode == "disable" {
		return fmt.Errorf("settings: POSTGRES_SSLMODE must not be 'disable' in production")
	}

	for name, raw := range map[string]string{
		"APP_PUBLIC_URL": s.Dockio.PublicURL, "APP_BASE_URL": s.Frontend.BaseURL, "DOCKIO_STATION_URL": s.Dockio.StationURL,
	} {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("settings: %s=%q is not an http(s) URL", name, raw)
		}
		// døckio refuses plain http except to a loopback host, and so do we.
		if s.IsProduction() && u.Scheme != "https" {
			return fmt.Errorf("settings: %s must be https in production", name)
		}
	}
	// The key in .env.example is public: everything sealed under it is readable
	// by anyone who has read this repository.
	if s.IsProduction() && s.Secrets.Key == DevSecretsKey {
		return fmt.Errorf("settings: SECRETS_KEY is the development key from .env.example; generate one with `openssl rand -base64 32`")
	}
	if s.Dockio.AppKey == "" || strings.ContainsAny(s.Dockio.AppKey, ": ") {
		return fmt.Errorf("settings: DOCKIO_APP_KEY must be non-empty and contain no ':' or spaces")
	}
	if s.Dockio.HomeRealm == "" {
		return fmt.Errorf("settings: DOCKIO_HOME_REALM must not be empty")
	}
	switch s.Dockio.MaxExpiryDays {
	case 90, 180, 365:
	default:
		return fmt.Errorf("settings: DOCKIO_MAX_EXPIRY_DAYS must be 90, 180 or 365")
	}
	if s.Dockio.PermissionCacheTTL <= 0 || s.Dockio.PermissionCacheTTL > 5*time.Minute {
		return fmt.Errorf("settings: DOCKIO_PERMISSION_CACHE_TTL must be between 0 and 5m -- it is how long a revoked permission keeps working")
	}

	// A wildcard origin plus bearer-token auth is the exact configuration the CORS
	// spec forbids: it would let every site on the internet make authenticated
	// calls with your users' tokens.
	for _, origin := range s.CORS.AllowedOrigins {
		if origin == "*" && s.IsProduction() {
			return fmt.Errorf("settings: CORS_ALLOWED_ORIGINS must not contain '*' in production -- this API authenticates with bearer tokens, and a wildcard origin would expose them to every site on the internet")
		}
	}

	if s.RateLimit.Enabled && (s.RateLimit.Attempts <= 0 || s.RateLimit.Window <= 0) {
		return fmt.Errorf("settings: RATE_LIMIT_ATTEMPTS and RATE_LIMIT_WINDOW must be positive when the limiter is enabled")
	}

	return nil
}
