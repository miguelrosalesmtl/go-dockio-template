// Package server wires the HTTP API: routing, middleware, and lifecycle.
package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/miguelrosalesmtl/go-dockio-template/internal/identity"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/settings"
)

// Server holds the HTTP server and its dependencies.
type Server struct {
	http     *http.Server
	identity *identity.Service
	pool     *pgxpool.Pool
	log      *slog.Logger
	errors   errorHandler
	cfg      Config
	limiter  *limiter // nil when disabled
	done     chan struct{}
}

// Config is what a Server is built from.
type Config struct {
	Server    settings.Server
	RateLimit settings.RateLimit
	CORS      settings.CORS
	Auth      settings.Auth
	Frontend  settings.Frontend
	Debug     bool
	Identity  *identity.Service
	Pool      *pgxpool.Pool
	Log       *slog.Logger
}

// New builds a Server with every route registered.
func New(cfg Config) *Server {
	s := &Server{
		identity: cfg.Identity,
		pool:     cfg.Pool,
		log:      cfg.Log,
		errors:   errorHandler{log: cfg.Log, debug: cfg.Debug, pool: cfg.Pool},
		cfg:      cfg,
		done:     make(chan struct{}),
	}
	if len(cfg.CORS.AllowedOrigins) > 0 {
		cfg.Log.Info("CORS enabled", slog.Any("origins", cfg.CORS.AllowedOrigins))
	}
	if cfg.RateLimit.Enabled {
		s.limiter = newLimiter(cfg.RateLimit)
		go s.limiter.runReaper(s.done)
	} else {
		cfg.Log.Warn("RATE LIMITING IS DISABLED: the emergency sign-in is open to brute force")
	}
	s.http = &http.Server{
		Addr:         cfg.Server.Addr(),
		Handler:      s.routes(),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}
	return s
}

// routes is the whole API surface on one screen. Read it top to bottom and you
// can see exactly which middleware guards which endpoint.
func (s *Server) routes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(securityHeaders)
	r.Use(s.cors)
	r.Use(requestLogger(s.log))
	// Request id, IP and user agent on every audit entry written in this request.
	r.Use(s.withAuditMeta)

	r.Get("/healthz", s.handleHealth)
	r.Get("/readyz", s.handleReady)

	r.Route("/api/v1", func(r chi.Router) {
		// --- Public. ----------------------------------------------------------
		//
		// The døckio round trips land here, and none of them can carry a session:
		// the browser comes back from another site, or the caller is døckio
		// itself. Each is bound some other way -- a state cookie, a signature --
		// and each says how in its handler.

		r.Get("/permissions", s.handleListPermissions)
		r.Get("/auth/config", s.handleAuthConfig)

		// Sign-in through døckio. The browser navigates to /login, goes to døckio,
		// and comes back to /callback with a code.
		r.With(s.rateLimit(s.byIP("signin"))).Get("/auth/oidc/login", s.handleSigninStart)
		r.With(s.rateLimit(s.byIP("signin-callback"))).Get("/auth/oidc/callback", s.handleSigninCallback)
		r.Get("/auth/signed-out", s.handleSignedOut)

		// The emergency sign-in for the local superuser. Nothing links to it.
		r.With(s.rateLimit(s.byIPAndEmail("admin-login"))).Post("/auth/admin-login", s.handleAdminLogin)

		// døckio calling us: signed tokens, verified against the connection's keys.
		r.With(s.rateLimit(s.byIP("dockio-notice"))).Post("/auth/oidc/backchannel-logout", s.handleBackchannelLogout)
		r.With(s.rateLimit(s.byIP("dockio-notice"))).Post("/dockio/connection-revoked", s.handleConnectionRevoked)
		r.Get("/dockio/manifest", s.handleManifest)
		// Back from Quick connect. Bound to the browser by a state cookie and to
		// the person by the attempt row; see identity.CompleteConnect.
		r.With(s.rateLimit(s.byIP("connect-callback"))).Get("/auth/oidc/connect/callback", s.handleConnectCallback)

		// --- Signed in, no organization yet. ---------------------------------
		r.Group(func(r chi.Router) {
			r.Use(s.requireAuth)
			r.Use(s.sessionOnly)
			r.Use(s.csrf)

			r.Post("/auth/logout", s.handleLogout)
			r.Get("/auth/me", s.handleMe)
			r.Get("/auth/sessions", s.handleListSessions)
			r.Delete("/auth/sessions/{sessionID}", s.handleRevokeSession)
			r.Get("/organizations", s.handleListOrganizations)
		})

		// --- System: the operator's own staff. -------------------------------
		//
		// System permissions come from døckio's home realm (or the local
		// superuser holds them all). Without the permission the answer is 404:
		// the system surface does not advertise itself.
		r.Route("/system", func(r chi.Router) {
			r.Use(s.requireAuth)
			r.Use(s.sessionOnly)
			r.Use(s.csrf)

			r.Route("/signin", func(r chi.Router) {
				r.Use(s.requireSystem(identity.PermSystemSignin))
				r.Get("/", s.handleGetConnection)
				r.Patch("/", s.handleSetSigninEnabled)
				r.Post("/connect", s.handleConnectStart)
				r.Delete("/connection", s.handleDisconnect)
				r.Put("/manual", s.handleSaveManualConnection)
				r.Post("/catalog/sync", s.handleSyncCatalog)
			})
			r.Route("/organizations", func(r chi.Router) {
				r.Use(s.requireSystem(identity.PermSystemOrganizations))
				r.Get("/", s.handleSystemListOrganizations)
				r.Post("/", s.handleSystemCreateOrganization)
				r.Put("/{organizationID}/realm", s.handleSystemSetRealm)
				// Restoring HAS to live here: a deleted organization 404s for
				// everyone, its own people included.
				r.Post("/{organizationID}/restore", s.handleSystemRestoreOrganization)
			})
			r.Route("/users", func(r chi.Router) {
				r.Use(s.requireSystem(identity.PermSystemUsers))
				r.Get("/", s.handleSystemListUsers)
				r.Patch("/{userID}", s.handleSystemSetUserActive)
			})
		})

		// --- Organization-scoped. --------------------------------------------
		//
		// requireOrganization asks døckio what the caller may do in this
		// organization's realm. Each route names the ONE permission it needs, so
		// this block is the application's entire authorization policy. Your own
		// resources go here.
		//
		// People, roles and groups have no routes: they are managed in døckio.
		r.Route("/organizations/{organization}", func(r chi.Router) {
			r.Use(s.requireAuth)
			r.Use(s.csrf)
			r.Use(s.requireOrganization)

			r.With(s.requirePermission(identity.PermOrganizationRead)).Get("/", s.handleGetOrganization)
			r.With(s.requirePermission(identity.PermOrganizationUpdate)).Patch("/", s.handleUpdateOrganization)
			r.With(s.requirePermission(identity.PermOrganizationDelete)).Delete("/", s.handleDeleteOrganization)

			r.With(s.requirePermission(identity.PermAuditRead)).Get("/audit", s.handleListAuditLog)

			r.With(s.requirePermission(identity.PermAPIKeysRead)).Get("/api-keys", s.handleListAPIKeys)
			r.With(s.requirePermission(identity.PermAPIKeysCreate)).Post("/api-keys", s.handleCreateAPIKey)
			r.With(s.requirePermission(identity.PermAPIKeysDelete)).Delete("/api-keys/{keyID}", s.handleRevokeAPIKey)
		})
	})

	return r
}

// Start begins serving HTTP. It blocks until the server stops.
func (s *Server) Start() error {
	s.log.Info("http server listening", slog.String("addr", s.cfg.Server.Addr()))
	if err := s.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Shutdown drains in-flight requests, up to the caller's deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	s.log.Info("http server shutting down")
	close(s.done)
	return s.http.Shutdown(ctx)
}

// handleHealth is the liveness probe. It must not touch the database: a brief
// database blip would otherwise restart every replica.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReady is the readiness probe: a replica that cannot reach Postgres is
// taken out of the load balancer. It does not ask døckio -- a døckio outage must
// not take the whole API down, only the requests that need døckio's answer.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.pool.Ping(ctx); err != nil {
		s.log.Warn("readiness check failed", slog.String("error", err.Error()))
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}
