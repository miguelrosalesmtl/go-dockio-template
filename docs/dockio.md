# døckio in this template

døckio is the identity manager. This document is how the template uses it: who
owns what, the four flows (connect, sign-in, permissions, notices), what the front
end must do, and — at the end — every point where the code assumes something
about døckio's wire format that is not yet confirmed.

## 1. Who owns what

| Concept | Lives in | Notes |
| --- | --- | --- |
| The installation (the operator) | A døckio **tenant** | Owns the application's single OIDC client |
| An organization (the app's tenant) | A døckio **realm** of that tenant | `organizations.dockio_realm` links the two |
| A person | A **døckio account** | One account across every organization and every døckio app |
| Who belongs to an organization | **Realm membership** | Answered by døckio, never stored here |
| What a person may do there | **Roles in that realm**, over the app's permission keys | døckio computes it; the app asks |
| Passwords, passkeys, 2FA, invitations, their mail | **døckio** | The app sends none and stores none |
| The application's own staff | The **home realm** | System permissions are granted there |

The application stores a local `users` row per døckio account it has seen, linked
by **(issuer, uid)** in `oidc_identities` — never by `sub`, username or email,
all of which can change. Name and email on that row are copies, refreshed at every
sign-in.

The only local credential is the **break-glass superuser**: created from the CLI,
signed in on an unlinked page, and audited on every organization it enters. It
exists because døckio cannot let anybody in before the application is connected,
nor after the connection has died.

## 2. Connecting (SOIDC v1 §14, "Quick connect")

One OIDC client serves the whole installation. An operator with
`system.signin` (or the local superuser) makes it from the sign-in settings page.

```
SPA                    API                                   browser          døckio
 │ POST /system/signin/connect ─► discovery of the station (every endpoint on its origin)
 │                                store attempt: sha256(state), sealed PKCE verifier, 10 min
 │ ◄── {redirect_url} + Lax cookie(state), path = the callback
 │ window.location.assign(redirect_url) ────────────────────────► /connect?manifest_uri&return_uri&state&code_challenge
 │                                                       døckio GETs /api/v1/dockio/manifest
 │                                                       operator signs in, picks tenant + lifetime, approves
 │                                ◄───────────────────────────── 302 /api/v1/auth/oidc/connect/callback?code&state
 │                                cookie == state? take the attempt (single use)
 │                                the person may STILL change sign-in?
 │                                POST connect token endpoint {code, code_verifier, return_uri}
 │                                validate the grant, save (secret sealed), sync the catalog
 │ ◄── 302 {SIGNIN_SETTINGS_PATH}?connected=1 | ?renewed=1 | ?connect_error=<code>
```

- **A first connect leaves sign-in off.** An admin reviews the connection, then
  turns it on (`PATCH /system/signin {"enabled": true}`). A renewal keeps it as it
  was.
- **Renew** is the same round trip with `{"renew": true}`; døckio rotates the secret
  of the same connection, and the previous secret keeps working for 10 minutes.
- **Reconnect** after a revocation is a fresh connect to the same station. A tenant
  that already holds the app keeps its client and everything it provisioned.
- **Disconnect** (`DELETE /system/signin/connection`) revokes at døckio and
  always clears locally, even when døckio cannot be reached; the answer says
  whether døckio was told (`dockio_told`).
- **Manual setup** (`PUT /system/signin/manual`) is the fallback for a station
  without §14. It never expires, and starts with sign-in off too.

Connection status is computed, never stored: `none`, `manual`, `active`,
`expiring` (30 days or less), `expired`, `revoked`. Expired and revoked stop
sign-in at both ends — starting it and completing it — but the settings are kept
so Renew and Reconnect stay one click.

## 3. Signing in

The API is a **backend-for-frontend**. The browser holds only a session cookie
(`HttpOnly`, `SameSite=Lax`, `Secure` in production); every døckio token stays on
the server.

```
GET /api/v1/auth/oidc/login[?organization=<slug>][&return_to=/path]
    -> 302 døckio (authorization code + PKCE), Lax state cookie
GET /api/v1/auth/oidc/callback?code&state
    -> verify the id token (signature, issuer by origin AND path, audience, nonce, lifetime, uid)
    -> link the account by (issuer, uid), create a session
    -> 302 {APP_BASE_URL}{return_to}, with the session cookie
    -> or 302 {APP_BASE_URL}{LOGIN_PATH}?error=<code>
```

- `?organization=<slug>` is what a business's own sign-in page (`/b/<slug>` in the
  front end) uses. døckio shows that realm's branding, and the person **must**
  come back signed in to exactly that realm (`wrong_realm` otherwise). Isolation
  at sign-in is the application's job.
- `POST /api/v1/auth/logout` ends the session and answers `{"logout_url"}`: the
  front end navigates there to end the døckio session too. døckio returns the
  browser to `/api/v1/auth/signed-out`, which redirects to the login page with
  `?signed_out=1`.
- døckio's **back-channel logout** (`POST /api/v1/auth/oidc/backchannel-logout`,
  form field `logout_token`) ends one døckio session (`sid`) or every session of
  an account (`uid`). With a `dockio_realm` claim, the person stays signed in but
  is no longer offered that realm's organizations.

## 4. Permissions

Permissions are **defined in code** (`internal/identity/permissions.go`) and
published to døckio — the catalog sync — on every connect and at startup. døckio
stores roles over those keys and computes who holds what.

| In code | Published to døckio as | Checked |
| --- | --- | --- |
| `apikeys.create` | `<DOCKIO_APP_KEY>:biz:apikeys:create` | inside an organization, from its realm |
| `system.signin` | `<DOCKIO_APP_KEY>:system:signin` | on the system surface, from the home realm |

- **Implication lives in one place** (`PermissionSet.Has`): any level of a resource
  implies its `read`. Roles in døckio still hold explicit keys.
- **Every organization request** asks døckio for the person's effective keys in
  the organization's realm, caches the answer per (account, realm) for
  `DOCKIO_PERMISSION_CACHE_TTL` (60 s), and **fails closed**: when døckio cannot be
  reached and the last answer is older than that, the request is a 503.
- The answer must be about the account that was asked about (`id` = the linked
  uid), and the person must be in the realm.
- `system.superuser` held in the home realm, or the local superuser, enters every
  organization with every permission. Each such request writes
  `superuser.organization_accessed` before it is served; if that write fails, the
  request is refused.
- **Bump `CatalogVersion`** on every change to the catalog. døckio refuses an older
  version than the one it holds: a rolled-back deploy is noticed, and the keys it
  lacks stay deprecated in døckio rather than being deleted.

API keys are the application's own, per organization, scoped by the same catalog.
A key cannot be minted with more than its creator holds. It acts as its creator
but carries a **frozen** scope: revoke it if its creator loses access in døckio.

## 5. What the front end must do

- Send `X-CSRF-Protection: 1` on every state-changing request made with the
  session cookie. Requests with a bearer token need not.
- Read `GET /api/v1/auth/config`. When `unavailable` is true, say "an administrator
  must renew the døckio connection" instead of showing a broken button.
- Read `GET /api/v1/auth/me` for `system_permissions`. People holding
  `system.signin` should see an app-wide banner from 30 days before expiry, on
  expiry and on revocation (from `GET /api/v1/system/signin`: `status`,
  `days_left`), with a Renew or Reconnect button. Nobody should learn of it from a
  locked-out user.
- Map the codes it is redirected with to plain words:

| Code | Say |
| --- | --- |
| `signin_unavailable` | Sign-in is not available right now; an administrator must renew the døckio connection |
| `invalid_state` | That sign-in link has already been used or has expired; try again |
| `access_denied` | You cancelled, or døckio refused the sign-in |
| `signin_expired` | The sign-in took too long; try again |
| `connection_expired` | The døckio connection has expired; an administrator must renew it |
| `invalid_token` | døckio's answer could not be verified; try again |
| `wrong_realm` | You signed in to another organization than the one you chose |
| `account_deactivated` | Your account has been deactivated here |
| `unknown_organization` | No such organization |
| `dockio_unavailable` | døckio could not be reached |
| `connect_cancelled` | You cancelled in døckio |
| `connect_expired` | The connect link expired; try again |
| `connect_forbidden` | You are no longer allowed to change sign-in |
| `connect_other_tenant` | Another tenant cannot be connected while organizations use this one |
| `connect_invalid_grant` | døckio's answer failed validation; nothing was saved |
| `internal` | Something went wrong on our side |

`POST /system/signin/connect` answers `409 {"error":"connect_not_supported"}` for a
døckio that cannot connect in one click: hide Quick connect and show manual setup.

## 6. Security checklist

| Rule | Where |
| --- | --- |
| The client secret never touches a browser; codes are exchanged server to server with PKCE S256 | `identity/connection.go`, `identity/signin.go` |
| Attempts store the state's hash, never the state; verifiers are sealed; attempts are single use and expire in 10 minutes | `identity/connection_repository.go` |
| Callbacks are bound to the browser (Lax cookie == state, constant time) and to the person (attempt row, permission re-checked) | `CompleteConnect`, `CompleteSignIn` |
| Discovery is validated: issuer = the address asked, every endpoint on its origin, https or loopback http | `dockio/discovery.go` |
| No redirect is ever followed on a call to døckio | `dockio.NewHTTPClient` |
| The grant is validated: required fields, issuer on the station, app_key, same connection and tenant on renewal | `validateGrant` |
| Tenant issuers are compared by origin AND path | `dockio.SameIssuer` |
| A tenant switch that would strand organizations is refused, and the new connection disconnected | `CompleteConnect` |
| A replaced connection is retired at døckio | `retire` |
| Revocation notices: body capped, signature, typ, iss, aud, exp, connection_id, iat after the last connect; a repeat is 204 | `ConnectionRevoked` |
| Expired or revoked stops sign-in at the start AND the callback | `StartSignIn`, `CompleteSignIn` |
| Redirects carry a code only, never a secret or an internal error | `server/handlers_auth.go` |
| `return_to` is a path on the front end, never a URL | `safeReturnTo` |
| Business data fails closed when døckio cannot answer | `identity/access.go` |

## 7. ASSUMPTIONS — confirm against SOIDC v1 before production

The connect flow (§14) follows the published integration guide. These points do
**not** come from a confirmed contract. Each is marked `ASSUMPTION` in the code,
and the fake station in `internal/dockio/dockiotest` implements the same
assumption, so the tests cannot catch a mismatch. Check each against døckio's
`docs/soidc/v1.md` and the real station before relying on it.

1. **Realm hint at sign-in.** The authorization request carries
   `dockio_realm=<realm>`, and the id token answers with a `realm` claim equal to it.
2. **Realms in the id token.** The id token lists the person's realms in a
   `dockio_realms` claim (an array of realm slugs).
3. **Account id.** The id token carries `uid`, the stable døckio account id, and
   `sid`, the døckio session id.
4. **Effective permissions per realm.** `GET {dockio_effective_permissions_endpoint}`
   with `{username}` substituted accepts `?realm=<realm>`, and answers
   `{"username","id","disabled","keys":[...],"realms":[...]}`. When `realms` is
   absent the code falls back to the realms from the id token.
5. **Application token scopes.** RP API calls ask for
   `dockio:catalog dockio:assignments`; disconnect asks for `dockio:connection`
   alone.
6. **Logout token claims.** A back-channel logout token may carry `uid` and
   `dockio_realm` besides the standard `sub`, `sid` and `events`.
7. **Client authentication** at the token endpoint is `client_secret_basic`, with
   the client id and secret form-encoded before Basic encoding (RFC 6749 §2.3.1).
8. **Catalog endpoint.** `PUT {dockio_catalog_endpoint}` takes
   `{"version", "permissions":[{"key","name","description","category"}]}` and
   answers 409 for an older version.

When døckio publishes its Go library, the hand-written client in
`internal/dockio` can be replaced by it behind the same functions.

## 8. Not here yet

- **Provisioning (SOIDC §12–§13):** creating realms, branding them, and creating
  default roles when an organization is created. Until then, create the realm in
  døckio's console and link it (`PUT /system/organizations/{id}/realm`).
- **People, invitations and groups** from inside the application. They are
  managed in døckio's console for now; the application only reads the answer.
