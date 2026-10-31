package identity

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestQuickConnectSavesASealedSecretAndLeavesSignInOff(t *testing.T) {
	e := newEnv(t)

	res, err := e.connect(e.admin, false)
	if err != nil || res != ConnectConnected {
		t.Fatalf("connect = %q, %v", res, err)
	}
	c, err := e.svc.repo.GetConnection(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if c.Enabled {
		t.Fatal("a first connect turned sign-in on; an admin must review it first")
	}
	if c.ConnectionID == nil || c.SecretExpiresAt == nil || c.HomeRealm == nil || *c.HomeRealm != "app" {
		t.Fatalf("connection fields not saved: %+v", c)
	}
	// The secret is stored sealed: nothing in the row is the secret itself.
	client := e.station.ClientByID(c.ClientID)
	if bytes.Contains(c.ClientSecretEnc, []byte(client.Secrets[len(client.Secrets)-1])) {
		t.Fatal("the client secret is stored in the clear")
	}
	// The catalog reached døckio, even with sign-in off.
	if cat := e.station.Catalog(); cat == nil || cat.Version != CatalogVersion {
		t.Fatalf("catalog not synced: %+v", cat)
	}
	if v, _ := e.svc.Connection(e.ctx); v.Status != StatusActive || v.CatalogVersion == nil {
		t.Fatalf("view = %+v", v)
	}
	if countAudit(t, "connection.connected") != 1 {
		t.Fatal("the connect was not audited")
	}
}

func TestRenewRotatesTheSecretAndKeepsSignInAsItWas(t *testing.T) {
	e := newEnv(t)
	before := e.connected()

	res, err := e.connect(e.admin, true)
	if err != nil || res != ConnectRenewed {
		t.Fatalf("renew = %q, %v", res, err)
	}
	after, _ := e.svc.repo.GetConnection(e.ctx)
	if *after.ConnectionID != *before.ConnectionID || after.ClientID != before.ClientID {
		t.Fatal("a renewal changed the connection or client")
	}
	if bytes.Equal(after.ClientSecretEnc, before.ClientSecretEnc) {
		t.Fatal("a renewal kept the old secret")
	}
	if !after.Enabled {
		t.Fatal("a renewal turned sign-in off")
	}
}

func TestTheConnectCallbackIsBoundToTheBrowserAndUsableOnce(t *testing.T) {
	e := newEnv(t)
	redirect, state, err := e.svc.StartConnect(e.ctx, e.admin, "", false)
	if err != nil {
		t.Fatal(err)
	}
	q := browse(t, redirect)

	// Another browser (no cookie, or another one) is refused, and that refusal
	// does not spend the attempt.
	if _, err := e.svc.CompleteConnect(e.ctx, "", q.Get("state"), q.Get("code"), ""); flowCode(err) != CodeInvalidState {
		t.Fatalf("no cookie: %v", err)
	}
	if _, err := e.svc.CompleteConnect(e.ctx, "another-state-value", q.Get("state"), q.Get("code"), ""); flowCode(err) != CodeInvalidState {
		t.Fatalf("wrong cookie: %v", err)
	}
	if _, err := e.svc.CompleteConnect(e.ctx, state, q.Get("state"), q.Get("code"), ""); err != nil {
		t.Fatalf("the right browser: %v", err)
	}
	if _, err := e.svc.CompleteConnect(e.ctx, state, q.Get("state"), q.Get("code"), ""); flowCode(err) != CodeInvalidState {
		t.Fatalf("reused attempt: %v", err)
	}
}

func TestCancellingInDockioSaysSo(t *testing.T) {
	e := newEnv(t)
	e.station.ConnectDenies = true
	if _, err := e.connect(e.admin, false); flowCode(err) != CodeConnectCancelled {
		t.Fatalf("err = %v, want connect_cancelled", err)
	}
	if _, err := e.svc.repo.GetConnection(e.ctx); !errors.Is(err, ErrNotConnected) {
		t.Fatal("a cancelled connect saved something")
	}
}

func TestAStationWithoutConnectIsRefusedUpFront(t *testing.T) {
	e := newEnv(t)
	e.station.NoConnect = true
	if _, _, err := e.svc.StartConnect(e.ctx, e.admin, "", false); !errors.Is(err, ErrConnectNotSupported) {
		t.Fatalf("err = %v, want ErrConnectNotSupported", err)
	}
}

func TestAGrantForAnotherAppIsRefused(t *testing.T) {
	e := newEnv(t)
	e.station.GrantHook = func(g map[string]any) { g["app_key"] = "someone-else" }
	if _, err := e.connect(e.admin, false); flowCode(err) != CodeConnectInvalidGrant {
		t.Fatalf("err = %v, want connect_invalid_grant", err)
	}
}

func TestAGrantWhoseIssuerIsOnAnotherStationIsRefused(t *testing.T) {
	e := newEnv(t)
	e.station.GrantHook = func(g map[string]any) { g["issuer"] = "https://elsewhere.example/t/acme" }
	if _, err := e.connect(e.admin, false); flowCode(err) != CodeConnectInvalidGrant {
		t.Fatalf("err = %v, want connect_invalid_grant", err)
	}
}

func TestAnotherTenantIsRefusedWhileOrganizationsUseThisOneAndTheNewConnectionIsDisconnected(t *testing.T) {
	e := newEnv(t)
	e.connected()
	if _, err := e.svc.CreateOrganization(e.ctx, e.admin, "shop", "Shop", "r-shop"); err != nil {
		t.Fatal(err)
	}

	// Same station, same origin, another tenant: an origin-only check would let
	// this through.
	e.station.ConnectTenant = "elsewhere"
	var refusedClient string
	e.station.GrantHook = func(g map[string]any) { refusedClient = g["client_id"].(string) }
	if _, err := e.connect(e.admin, false); flowCode(err) != CodeConnectOtherTenant {
		t.Fatalf("err = %v, want connect_other_tenant", err)
	}
	if !e.station.ClientByID(refusedClient).Revoked {
		t.Fatal("the refused connection was left live in døckio")
	}
}

func TestPermissionLostBetweenStartAndCallbackIsRefused(t *testing.T) {
	e := newEnv(t)
	redirect, state, err := e.svc.StartConnect(e.ctx, e.admin, "", false)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := e.svc.CreateSuperuser(e.ctx, "ops@example.com", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SetUserActive(e.ctx, other, e.admin.ID, false); err != nil {
		t.Fatal(err)
	}
	q := browse(t, redirect)
	if _, err := e.svc.CompleteConnect(e.ctx, state, q.Get("state"), q.Get("code"), ""); flowCode(err) != CodeConnectForbidden {
		t.Fatalf("err = %v, want connect_forbidden", err)
	}
}

func TestDisconnectTellsDockioAndClearsLocally(t *testing.T) {
	e := newEnv(t)
	c := e.connected()

	told, err := e.svc.Disconnect(e.ctx, e.admin)
	if err != nil || !told {
		t.Fatalf("disconnect = %v, %v", told, err)
	}
	if !e.station.ClientByID(c.ClientID).Revoked {
		t.Fatal("døckio was not told")
	}
	if _, err := e.svc.repo.GetConnection(e.ctx); !errors.Is(err, ErrNotConnected) {
		t.Fatal("the connection is still stored")
	}
}

func TestDisconnectStillClearsLocallyWhenDockioIsDown(t *testing.T) {
	e := newEnv(t)
	e.connected()
	e.svc.forgetClient()
	e.station.Close()

	told, err := e.svc.Disconnect(e.ctx, e.admin)
	if err != nil || told {
		t.Fatalf("disconnect = %v, %v; want cleared locally, døckio not told", told, err)
	}
	if _, err := e.svc.repo.GetConnection(e.ctx); !errors.Is(err, ErrNotConnected) {
		t.Fatal("disconnect must always clear locally")
	}
}

func TestARevocationNoticeRevokesAndStopsSignIn(t *testing.T) {
	e := newEnv(t)
	c := e.connected()

	if err := e.svc.ConnectionRevoked(e.ctx, e.station.SignRevocation(c.ClientID, time.Now().Add(time.Second))); err != nil {
		t.Fatalf("notice: %v", err)
	}
	if v, _ := e.svc.Connection(e.ctx); v.Status != StatusRevoked {
		t.Fatalf("status = %q, want revoked", v.Status)
	}
	if ok, _ := e.svc.SigninAvailable(e.ctx); ok {
		t.Fatal("sign-in is still available over a revoked connection")
	}
	if _, _, err := e.svc.StartSignIn(e.ctx, "", "/"); flowCode(err) != CodeSigninUnavailable {
		t.Fatalf("start sign-in: %v, want signin_unavailable", err)
	}
	// døckio retries until it gets a 2xx: a repeat must succeed, not 400.
	if err := e.svc.ConnectionRevoked(e.ctx, e.station.SignRevocation(c.ClientID, time.Now().Add(time.Second))); err != nil {
		t.Fatalf("repeat: %v, want nil", err)
	}
}

func TestStaleForgedAndForeignNoticesChangeNothing(t *testing.T) {
	e := newEnv(t)
	c := e.connected()

	// Issued before the current connection was made: a replay.
	if err := e.svc.ConnectionRevoked(e.ctx, e.station.SignRevocation(c.ClientID, time.Now().Add(-time.Hour))); !errors.Is(err, ErrInvalidNotice) {
		t.Fatalf("stale: %v", err)
	}
	// For another client.
	other, _ := e.station.RegisterClient("acme")
	if err := e.svc.ConnectionRevoked(e.ctx, e.station.SignRevocation(other, time.Now())); !errors.Is(err, ErrInvalidNotice) {
		t.Fatalf("other client: %v", err)
	}
	// Garbage.
	if err := e.svc.ConnectionRevoked(e.ctx, "not.a.token"); !errors.Is(err, ErrInvalidNotice) {
		t.Fatalf("garbage: %v", err)
	}
	if v, _ := e.svc.Connection(e.ctx); v.Status != StatusActive {
		t.Fatalf("status = %q, want still active", v.Status)
	}
	if countAudit(t, "connection.notice_rejected") < 2 {
		t.Fatal("rejected notices were not audited")
	}
}

func TestStatusIsComputedFromTheDates(t *testing.T) {
	now := time.Now()
	id := "conn"
	at := func(d time.Duration) *time.Time { x := now.Add(d); return &x }
	for _, tc := range []struct {
		c    ConnectionSettings
		want string
	}{
		{ConnectionSettings{}, StatusManual},
		{ConnectionSettings{ConnectionID: &id, SecretExpiresAt: at(90 * 24 * time.Hour)}, StatusActive},
		{ConnectionSettings{ConnectionID: &id, SecretExpiresAt: at(29 * 24 * time.Hour)}, StatusExpiring},
		{ConnectionSettings{ConnectionID: &id, SecretExpiresAt: at(-time.Minute)}, StatusExpired},
		{ConnectionSettings{ConnectionID: &id, SecretExpiresAt: at(-time.Minute), RevokedAt: at(-time.Hour)}, StatusRevoked},
	} {
		if got := tc.c.Status(now); got != tc.want {
			t.Errorf("status = %q, want %q", got, tc.want)
		}
	}
}

func TestManualSetupNeverExpiresAndStartsOff(t *testing.T) {
	e := newEnv(t)
	id, secret := e.station.RegisterClient("acme")
	if err := e.svc.SaveManualConnection(e.ctx, e.admin, e.station.Issuer("acme"), id, secret); err != nil {
		t.Fatal(err)
	}
	v, _ := e.svc.Connection(e.ctx)
	if v.Status != StatusManual || v.Enabled || v.ExpiresAt != nil {
		t.Fatalf("view = %+v", v)
	}
	if err := e.svc.SaveManualConnection(e.ctx, e.admin, "http://døck.io/t/acme", id, secret); !errors.Is(err, ErrValidation) {
		t.Fatalf("plain http to a non-loopback host: %v, want a validation error", err)
	}
}
