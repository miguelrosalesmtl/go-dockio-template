// Command server is the application entrypoint.
//
// Modes, chosen by the first argument:
//
//	server                            start the HTTP API
//	server migrate up|down|...        apply the embedded migrations, then exit
//	server create-superuser <email>   create a local superuser, or set a new password
//	server delete-superuser <email>   remove one
//	server purge                      DESTROY data past its retention (privileged)
//
// The migrate mode is why the same image can be both the app and its own
// migrator: docker-compose runs it as a one-shot job the app waits on, and
// Kubernetes runs the identical container as an init container or Job.
//
// The superuser commands live here, rather than behind an HTTP route, so that the
// one credential that bypasses døckio takes shell access to obtain -- not merely
// a stolen session.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/miguelrosalesmtl/go-dockio-template/internal/audit"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/database"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/identity"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/logger"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/secrets"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/server"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/settings"
)

// sessionCleanup controls the background pruning of dead session rows. Sessions
// are the only table here that grows without bound, so something has to sweep it.
const (
	cleanupInterval = 1 * time.Hour
	// Keep expired and revoked sessions around for a while before deleting them,
	// so they remain visible to an incident investigation.
	sessionRetention = 720 * time.Hour // 30 days
)

func main() {
	var err error

	subcommand := ""
	if len(os.Args) > 1 {
		subcommand = os.Args[1]
	}

	switch subcommand {
	case "migrate":
		err = runMigrate(os.Args[2:])
	case "create-superuser":
		err = runCreateSuperuser(os.Args[2:])
	case "delete-superuser":
		err = runDeleteSuperuser(os.Args[2:])
	case "purge":
		err = runPurge()
	case "":
		err = run()
	default:
		_, _ = os.Stderr.WriteString("unknown subcommand " + subcommand + "\n" + usage)
		os.Exit(2)
	}

	if err != nil {
		// The logger may not exist yet if settings failed, so fall back to stderr.
		_, _ = os.Stderr.WriteString("fatal: " + err.Error() + "\n")
		os.Exit(1)
	}
}

const usage = `usage:
  server                            start the HTTP API
  server migrate [up|down|status|reset]
  server create-superuser <email>   create a local superuser, or set a new password
                                    (the password is read from SUPERUSER_PASSWORD, or stdin)
  server delete-superuser <email>   remove one
  server purge                      DESTROY data past its retention (privileged)
`

// openService builds the identity service for a one-shot command.
func openService(ctx context.Context) (*identity.Service, func(), error) {
	cfg, err := settings.Load()
	if err != nil {
		return nil, nil, err
	}
	log := logger.New(cfg)
	pool, err := database.NewPool(ctx, cfg.Postgres)
	if err != nil {
		return nil, nil, err
	}
	box, err := newBox(cfg)
	if err != nil {
		pool.Close()
		return nil, nil, err
	}
	return newIdentity(cfg, pool, box, log), pool.Close, nil
}

// runCreateSuperuser handles `server create-superuser <email>`.
//
// The password comes from SUPERUSER_PASSWORD or, failing that, the first line of
// stdin -- never from an argument, which would land in shell history and in
// every process listing on the machine.
func runCreateSuperuser(args []string) error {
	if len(args) != 1 || args[0] == "" {
		return errors.New("expected exactly one argument: an email address")
	}
	password := os.Getenv("SUPERUSER_PASSWORD")
	if password == "" {
		fmt.Fprint(os.Stderr, "password: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return errors.New("no password: set SUPERUSER_PASSWORD or pipe it on stdin")
		}
		password = strings.TrimRight(line, "\r\n")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	svc, closeFn, err := openService(ctx)
	if err != nil {
		return err
	}
	defer closeFn()

	user, created, err := svc.CreateSuperuser(ctx, args[0], password)
	if err != nil {
		return err
	}
	if created {
		fmt.Printf("created superuser %s (%s)\n", user.Email, user.ID)
	} else {
		fmt.Printf("set a new password for superuser %s (%s); their sessions were ended\n", user.Email, user.ID)
	}
	return nil
}

// runDeleteSuperuser handles `server delete-superuser <email>`.
func runDeleteSuperuser(args []string) error {
	if len(args) != 1 || args[0] == "" {
		return errors.New("expected exactly one argument: an email address")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	svc, closeFn, err := openService(ctx)
	if err != nil {
		return err
	}
	defer closeFn()

	user, err := svc.DeleteSuperuser(ctx, args[0])
	if errors.Is(err, identity.ErrNotFound) {
		return fmt.Errorf("no superuser with email %q", args[0])
	}
	if err != nil {
		return err
	}
	fmt.Printf("deleted superuser %s (%s)\n", user.Email, user.ID)
	return nil
}

// newBox opens the key that seals the døckio client secret and friends.
func newBox(cfg *settings.Settings) (*secrets.Box, error) {
	key, err := secrets.ParseKey(cfg.Secrets.Key)
	if err != nil {
		return nil, fmt.Errorf("SECRETS_KEY: %w (generate one with: openssl rand -base64 32)", err)
	}
	return secrets.New(key)
}

func newIdentity(cfg *settings.Settings, pool *pgxpool.Pool, box *secrets.Box, log *slog.Logger) *identity.Service {
	return identity.NewService(pool, identity.Config{
		Auth: cfg.Auth, Dockio: cfg.Dockio, Frontend: cfg.Frontend, Secrets: box, Log: log,
	})
}

// runMigrate handles the `migrate` subcommand. Direction defaults to "up".
func runMigrate(args []string) error {
	direction := "up"
	if len(args) > 0 {
		direction = args[0]
	}

	cfg, err := settings.Load()
	if err != nil {
		return err
	}
	return database.Migrate(cfg.Postgres, direction, logger.New(cfg))
}

func run() error {
	cfg, err := settings.Load()
	if err != nil {
		return err
	}

	log := logger.New(cfg)
	log.Info("starting", slog.String("environment", cfg.App.Environment))

	// Root context, cancelled on SIGINT/SIGTERM -- the latter is what Kubernetes
	// and `docker compose down` send. Everything below hangs off it, so a signal
	// unwinds the whole process in order.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := database.NewPool(ctx, cfg.Postgres)
	if err != nil {
		return err
	}
	defer pool.Close()
	log.Info("connected to postgres",
		slog.String("host", cfg.Postgres.Host),
		slog.String("database", cfg.Postgres.Database),
	)

	box, err := newBox(cfg)
	if err != nil {
		return err
	}
	identityService := newIdentity(cfg, pool, box, log)

	// Mirror the permission catalog compiled into this binary into the database,
	// where the API key scopes reference it. Permissions come from code; roles
	// live in døckio. Adding a permission is a code change plus a restart.
	if err := identityService.SyncPermissions(ctx); err != nil {
		return err
	}

	go reap(ctx, identityService, log)

	// Publish the permission catalog to døckio, if connected. Best effort: a
	// døckio that is down must not stop the API from starting.
	go func() {
		if err := identityService.SyncCatalog(ctx); err != nil && !errors.Is(err, identity.ErrNotConnected) {
			log.Warn("could not publish the permission catalog to døckio at startup", slog.String("error", err.Error()))
		}
	}()

	srv := server.New(server.Config{
		Server: cfg.Server, RateLimit: cfg.RateLimit, CORS: cfg.CORS, Auth: cfg.Auth, Frontend: cfg.Frontend,
		Debug: cfg.App.Debug, Identity: identityService, Pool: pool, Log: log,
	})

	serverErr := make(chan error, 1)
	go func() { serverErr <- srv.Start() }()

	// Block until the server dies on its own or a shutdown signal arrives.
	select {
	case err := <-serverErr:
		return err
	case <-ctx.Done():
		log.Info("shutdown signal received")
	}

	// Drain in-flight requests, but not forever. The deadline hangs off
	// context.Background(), not ctx -- ctx is already cancelled, and a shutdown
	// context derived from it would expire instantly and drop every live request.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("graceful shutdown failed", slog.String("error", err.Error()))
		return err
	}
	log.Info("shutdown complete")
	return nil
}

// reap prunes the short-lived tables: dead sessions, and sign-in and connect
// attempts that were never completed. They grow without bound and nothing else
// would ever remove them.
//
// Every replica runs this. That is harmless -- the DELETEs are idempotent and the
// duplicated work is a couple of indexed statements an hour -- and it means the
// cleanup needs no leader election and no separate cron deployment.
//
// It does NOT purge the audit log or destroy soft-deleted organizations. That is `server
// purge`, a separate command you schedule yourself, because destroying history
// should be a deliberate act rather than something a long-running process does on
// a ticker.
//
// Note what is NOT enforcing that separation: database privileges. This template
// runs a SINGLE user that owns the database, so the app holds DELETE on every table
// in it, audit_log included -- the append-only trigger guards against mistakes, not
// against code already running as the app. Keeping destruction out of the app is a
// discipline here, not a guarantee. See internal/audit/audit.go for the two-identity
// design that would make it one.
func reap(ctx context.Context, svc *identity.Service, log *slog.Logger) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			deleted, err := svc.CleanupSessions(ctx, sessionRetention)
			if err != nil {
				// Not fatal: the app serves fine with a few stale rows, and the next
				// tick will try again.
				log.Warn("session cleanup failed", slog.String("error", err.Error()))
			} else if deleted > 0 {
				log.Info("pruned dead sessions and expired sign-in attempts", slog.Int64("count", deleted))
			}
		}
	}
}

// runPurge handles `server purge`. It DESTROYS DATA, permanently.
//
// It is a separate command rather than something the running app does on a ticker,
// because destroying an audit trail should be a deliberate act -- exactly like a
// migration. Run it as a cron job or a Kubernetes CronJob, with the same connection
// settings the `migrate` job uses:
//
//	server purge
//
// BE CLEAR ABOUT WHAT SEPARATES IT, THOUGH: not database privileges. This template
// runs a single user that owns the database, so the app connects as `app` and holds
// DELETE on audit_log just as this command does -- code running as the app could do
// everything below if it were compromised into trying (see the append-only trigger
// in the baseline migration, which guards against mistakes, not against an adversary).
// Splitting into a privileged identity for this command and a restricted one for the
// app is the change that would turn this convention into an actual boundary.
//
// It honours AUDIT_RETENTION and ORGANIZATION_RETENTION, both of which default to 0 --
// "keep forever" -- so with no configuration this command does nothing at all.
func runPurge() error {
	cfg, err := settings.Load()
	if err != nil {
		return err
	}
	log := logger.New(cfg)

	if cfg.Audit.Retention <= 0 && cfg.Organization.Retention <= 0 {
		log.Info("nothing to purge: both AUDIT_RETENTION and ORGANIZATION_RETENTION are 0 (keep forever)")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	pool, err := database.NewPool(ctx, cfg.Postgres)
	if err != nil {
		return err
	}
	defer pool.Close()

	box, err := newBox(cfg)
	if err != nil {
		return err
	}
	svc := newIdentity(cfg, pool, box, log)

	// Organizations first: the cascade takes their audit entries with it, so purging them
	// before the audit sweep saves the sweep the work.
	if cfg.Organization.Retention > 0 {
		n, err := svc.PurgeDeletedOrganizations(ctx, cfg.Organization.Retention)
		if err != nil {
			return fmt.Errorf("purge organizations: %w", err)
		}
		log.Warn("PERMANENTLY DESTROYED soft-deleted organizations and every row they owned",
			slog.Int64("organizations", n),
			slog.Duration("retention", cfg.Organization.Retention),
		)
	}

	if cfg.Audit.Retention > 0 {
		var n int64
		err := database.InTx(ctx, pool, func(db database.DB) error {
			var err error
			n, err = audit.NewRecorder(db).Purge(ctx, cfg.Audit.Retention)
			return err
		})
		if err != nil {
			return fmt.Errorf("purge audit log: %w", err)
		}
		log.Warn("PERMANENTLY DESTROYED audit entries",
			slog.Int64("entries", n),
			slog.Duration("retention", cfg.Audit.Retention),
		)
	}
	return nil
}
