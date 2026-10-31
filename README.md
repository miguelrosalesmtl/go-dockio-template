# go-dockio-template

A Go starting point for multi-tenant SaaS backends whose identity is managed by
**døckio**. Organizations, server-side sessions, API keys, an append-only audit log,
and the whole døckio integration — Quick connect, sign-in, permissions, revocation
and logout notices — working and tested, plus the Postgres, Docker and
configuration plumbing.

The application has **no identity system of its own**. It stores no passwords for
normal users, sends no invitation or password mail, and has no 2FA of its own: all
of that is døckio's. What a person may do in an organization is døckio's answer,
asked on every request and cached for 60 seconds.

## Start a project with it

```sh
cp -r go-dockio-template my-project && cd my-project
rm -rf .git && git init
make rename m=github.com/you/my-project   # rewrite the module path everywhere
make env                                  # .env from .env.example
make up                                   # Postgres + migrations + app on :8080
```

Then, on day one:

```sh
# The emergency superuser: the only local credential, and the way in before
# døckio is connected. The password comes from the environment or stdin.
docker compose exec -e SUPERUSER_PASSWORD='a-long-password-here' app /app/server create-superuser you@example.com
```

Sign in with it (`POST /api/v1/auth/admin-login`), open the sign-in settings page
of your front end, click **Quick connect**, approve in døckio, review, and turn
sign-in on. From then on people sign in with døckio.

> døckio must be able to reach `APP_PUBLIC_URL` to fetch the manifest and post
> notices. A stack on your laptop therefore needs a døckio on your laptop too.

## What you get

| Concern | Where | Notes |
| --- | --- | --- |
| døckio client | `internal/dockio` | Discovery, Quick connect (§14), code flow + PKCE, id-token, logout-token and revocation verification (RS256 over JWKS), catalog sync, effective permissions. Standard library + `x/net/idna`. |
| Fake døckio | `internal/dockio/dockiotest` | An in-process station for tests: approves connects, signs people in, signs notices. |
| Identity | `internal/identity` | The connection, sign-in, access decisions, the local superuser, organizations, users, API keys. |
| Permissions | `internal/identity/permissions.go` | Defined in code, published to døckio. Implication (write ⇒ read) lives in one place. |
| Secrets | `internal/secrets` | AES-256-GCM sealing for what the server must read back: the client secret, PKCE verifiers, id tokens. |
| Audit | `internal/audit` | Append-only (a trigger), records denials, searchable, keyset-paginated. |
| HTTP | `internal/server` | chi, every route on one screen, cookie or bearer auth, CSRF, CORS, security headers, rate limits. |
| Config | `internal/settings` | One typed struct from env vars; refuses unsafe production configurations. |
| Database | `internal/database`, `migrations/` | pgx, embedded goose migrations, one clean baseline. Postgres 18+. |

**[docs/dockio.md](docs/dockio.md) is the integration in full**: who owns what,
each flow, what the front end must do, the security checklist, and — read this
before production — the list of points where the code assumes something about
døckio's wire format that is not yet confirmed.

## The model

| Here | In døckio |
| --- | --- |
| The installation | A tenant, owning one OIDC client |
| An organization (`organizations.dockio_realm`) | A realm: its members, roles, groups |
| A user row, linked by (issuer, uid) | An account |
| A permission key (`apikeys.create`) | `<app_key>:biz:apikeys:create`, granted by roles in the realm |
| A system permission (`system.signin`) | `<app_key>:system:signin`, granted in the home realm |

An organization is entered through its realm. Its people, roles and groups are
managed in døckio; the application has no member, role or invitation tables.

## The API

```
Public
GET    /healthz, /readyz
GET    /api/v1/permissions                       the catalog
GET    /api/v1/auth/config                       {signin_available}
GET    /api/v1/auth/oidc/login[?organization=&return_to=]   -> døckio
GET    /api/v1/auth/oidc/callback                <- døckio; sets the session cookie
GET    /api/v1/auth/signed-out                   <- døckio after sign-out
POST   /api/v1/auth/admin-login                  the emergency superuser   (rate limited)
POST   /api/v1/auth/oidc/backchannel-logout      døckio's logout token
POST   /api/v1/dockio/connection-revoked         døckio's revocation notice
GET    /api/v1/dockio/manifest                   what døckio fetches during Quick connect
GET    /api/v1/auth/oidc/connect/callback        <- døckio after Quick connect

Signed in
POST   /api/v1/auth/logout                       -> {logout_url} to end the døckio session too
GET    /api/v1/auth/me                           user, auth method, system permissions
GET    /api/v1/auth/sessions, DELETE /api/v1/auth/sessions/{id}
GET    /api/v1/organizations                     the organizations the person is offered

System (each group needs one system permission; 404 without it)
GET|PATCH /api/v1/system/signin                  the connection; {"enabled": bool}
POST   /api/v1/system/signin/connect             {station_url?, renew?} -> {redirect_url}
DELETE /api/v1/system/signin/connection          -> {dockio_told}
PUT    /api/v1/system/signin/manual              {issuer, client_id, client_secret}
POST   /api/v1/system/signin/catalog/sync
GET|POST /api/v1/system/organizations            create with {slug, name, dockio_realm}
PUT    /api/v1/system/organizations/{id}/realm   {dockio_realm}
POST   /api/v1/system/organizations/{id}/restore
GET    /api/v1/system/users, PATCH /api/v1/system/users/{id}  {is_active}

Organization-scoped (permissions from døckio, per request)
GET|PATCH|DELETE /api/v1/organizations/{organization}/
GET    /api/v1/organizations/{organization}/audit
GET|POST /api/v1/organizations/{organization}/api-keys, DELETE .../api-keys/{id}
```

A browser authenticates with the session cookie and must send
`X-CSRF-Protection: 1` on every state-changing request. A script uses a bearer
token: an API key (`key_…`) or a session token (`sess_…`).

## Adding your own organization-scoped resource

1. **Migration** — `migrations/00002_widgets.sql`, with
   `organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE`.
2. **Permissions** — add `widgets.read`, `widgets.write`… to `Catalog` in
   `internal/identity/permissions.go` and **bump `CatalogVersion`**. They are
   published to døckio at the next startup, where roles can grant them.
3. **Package** — `internal/widgets`, following `internal/identity`: a repository
   taking `database.DB`, and a service holding the rules. Every query on the table
   takes `organizationID` and puts it in the `WHERE` clause.
4. **Routes** — inside the `/organizations/{organization}` block in
   `internal/server/server.go`, each guarded by the one permission it needs.
5. **Audit** — record inside the same transaction as the write.
6. **Isolation test** — prove organization A cannot touch organization B's widgets.

## Commands

```
server                            start the HTTP API
server migrate up|down|status|reset
server create-superuser <email>   create a local superuser, or set a new password
                                  (SUPERUSER_PASSWORD, or the first line of stdin)
server delete-superuser <email>
server purge                      destroy data past AUDIT_RETENTION / ORGANIZATION_RETENTION
```

## Testing

```sh
make test              # unit tests; integration tests SKIP without a database
make test-integration  # starts a throwaway Postgres, runs everything
make test-e2e          # drives the running stack over real HTTP (needs `make up`)
make lint
```

The integration tests run against a **real Postgres** and the **fake døckio**: the
connect, renew, revoke and disconnect round trips; sign-in, account linking by uid,
realm isolation, back-channel logout; permission caching and failing closed when
døckio is down; the audit trigger; API-key scoping; and the HTTP wiring, cookies
and CSRF included. CI runs them with the race detector, a full migrate
down-and-back-up, an end-to-end suite against a running server, lint, and an image
build.

The fake station implements the same wire-format assumptions as the client, so the
tests cannot catch a mismatch with the real døckio. Before production, run the
flows once against a real station and check docs/dockio.md §7.

## Design notes

- **Sessions, not JWTs.** A session is a random token whose SHA-256 is stored;
  sign-out, deactivation and back-channel logout take effect on the next request.
- **Fail closed.** When døckio cannot be asked and the last answer is older than
  `DOCKIO_PERMISSION_CACHE_TTL`, organization requests are refused with a 503. An
  outage never signs anybody out, and never lets anybody in.
- **The audit log resists accidents, not a compromised app.** A trigger refuses
  `UPDATE`, `DELETE` and `TRUNCATE`, but the single database user can set the GUC
  it checks (`TestTheAppCanBypassTheAuditTriggerIfItWantsTo` says so). A second,
  restricted database identity is the change that would make it tamper-proof.
- **Isolation is enforced in the application.** Every organization-owned query
  filters by `organization_id`; there is no row-level security.
- **The rate limiter is per replica.** Put the real one at your proxy.

## Not here yet

- døckio **provisioning** (SOIDC §12–§13): creating a realm, branding it and
  creating default roles when an organization is created. Create the realm in
  døckio's console and link it for now.
- **People, invitations and groups** from inside the application. Manage them in
  døckio's console.

## Before production

- Confirm the wire-format assumptions in [docs/dockio.md](docs/dockio.md) §7.
- A real `SECRETS_KEY` (`openssl rand -base64 32`); startup refuses the example one.
- `APP_PUBLIC_URL` and `APP_BASE_URL` on https; `AUTH_SESSION_COOKIE_SECURE=true`.
- Alerting on `superuser.organization_accessed`, `access.escalation_denied`,
  `connection.revoked`, `connection.notice_rejected` and bursts of
  `users.login_failed`.
- A cron for `server purge` if you set a retention; TLS at your proxy, and
  `SERVER_TRUST_PROXY_HEADERS=true` only behind a proxy that overwrites
  `X-Forwarded-For`.
