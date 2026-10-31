package identity

import (
	"errors"
	"testing"
	"time"
)

// anaIn signs Ana in, with the shop organization linked to her realm.
func (e *env) anaIn() (User, Session) {
	e.t.Helper()
	e.connected()
	if _, err := e.svc.CreateOrganization(e.ctx, e.admin, "shop", "Shop", "r-shop"); err != nil {
		e.t.Fatal(err)
	}
	e.station.AddPerson(ana)
	e.station.SignIn = &ana
	res, err := e.signIn("")
	if err != nil {
		e.t.Fatal(err)
	}
	return e.session(res.Token)
}

func TestPermissionsComeFromDockioInTheOrganizationsRealm(t *testing.T) {
	e := newEnv(t)
	user, sess := e.anaIn()
	e.station.SetEffective("ana", "r-shop", wire(PermAPIKeysCreate), wire(PermAuditRead), "other-app:biz:x:read")

	access, err := e.svc.ResolveOrganization(e.ctx, user, sess, "shop")
	if err != nil {
		t.Fatal(err)
	}
	if !access.Can(PermAPIKeysCreate) || !access.Can(PermAuditRead) || access.Can(PermOrganizationDelete) {
		t.Fatalf("permissions = %v", access.Permissions.Slice())
	}
	// Implication: holding apikeys.create implies apikeys.read.
	if !access.Can(PermAPIKeysRead) {
		t.Fatal("apikeys.create did not imply apikeys.read")
	}
	if access.ViaSuperuser {
		t.Fatal("an ordinary member came in through the superuser bypass")
	}
}

func TestAnOrganizationInAnotherRealmIsNotFound(t *testing.T) {
	e := newEnv(t)
	user, sess := e.anaIn()
	if _, err := e.svc.CreateOrganization(e.ctx, e.admin, "bakery", "Bakery", "r-bakery"); err != nil {
		t.Fatal(err)
	}
	e.station.SetEffective("ana", "r-bakery", wire(PermOrganizationRead)) // keys, but not a member
	if _, err := e.svc.ResolveOrganization(e.ctx, user, sess, "bakery"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if _, err := e.svc.ResolveOrganization(e.ctx, user, sess, "no-such-org"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestARevokedPermissionStopsWorkingAfterOneCacheWindow(t *testing.T) {
	e := newEnv(t)
	user, sess := e.anaIn()
	e.station.SetEffective("ana", "r-shop", wire(PermAuditRead))
	if a, _ := e.svc.ResolveOrganization(e.ctx, user, sess, "shop"); !a.Can(PermAuditRead) {
		t.Fatal("setup: no audit.read")
	}

	e.station.SetEffective("ana", "r-shop")
	if a, _ := e.svc.ResolveOrganization(e.ctx, user, sess, "shop"); !a.Can(PermAuditRead) {
		t.Fatal("the cache was not used within its window")
	}
	e.svc.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if a, _ := e.svc.ResolveOrganization(e.ctx, user, sess, "shop"); a.Can(PermAuditRead) {
		t.Fatal("a revoked permission outlived the cache window")
	}
}

func TestRemovedFromTheRealmMeansNotFound(t *testing.T) {
	e := newEnv(t)
	user, sess := e.anaIn()
	e.station.SetEffective("ana", "r-shop", wire(PermAuditRead))
	e.station.RemoveFromRealm("ana", "r-shop")
	if _, err := e.svc.ResolveOrganization(e.ctx, user, sess, "shop"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestADockioOutageFailsClosedAfterTheCacheWindow(t *testing.T) {
	e := newEnv(t)
	user, sess := e.anaIn()
	e.station.SetEffective("ana", "r-shop", wire(PermAuditRead))
	if _, err := e.svc.ResolveOrganization(e.ctx, user, sess, "shop"); err != nil {
		t.Fatal(err)
	}
	e.station.Close()

	if a, err := e.svc.ResolveOrganization(e.ctx, user, sess, "shop"); err != nil || !a.Can(PermAuditRead) {
		t.Fatalf("within the window the last answer stands: %v", err)
	}
	e.svc.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if _, err := e.svc.ResolveOrganization(e.ctx, user, sess, "shop"); !errors.Is(err, ErrDockioUnavailable) {
		t.Fatalf("err = %v, want ErrDockioUnavailable (fail closed)", err)
	}
}

func TestSystemPermissionsComeFromTheHomeRealm(t *testing.T) {
	e := newEnv(t)
	user, sess := e.anaIn()

	perms, err := e.svc.SystemAccess(e.ctx, user, sess)
	if err != nil || perms.Has(PermSystemSignin) {
		t.Fatalf("Ana has no system permissions yet: %v %v", perms.Slice(), err)
	}
	e.station.SetEffective("ana", "app", wire(PermSystemSignin))
	e.svc.effective.clear()
	if perms, _ := e.svc.SystemAccess(e.ctx, user, sess); !perms.Has(PermSystemSignin) {
		t.Fatalf("perms = %v", perms.Slice())
	}
}

func TestSystemSuperuserFromDockioEntersEveryOrganization(t *testing.T) {
	e := newEnv(t)
	user, sess := e.anaIn()
	if _, err := e.svc.CreateOrganization(e.ctx, e.admin, "bakery", "Bakery", "r-bakery"); err != nil {
		t.Fatal(err)
	}
	e.station.SetEffective("ana", "app", wire(PermSystemSuperuser))
	a, err := e.svc.ResolveOrganization(e.ctx, user, sess, "bakery")
	if err != nil || !a.ViaSuperuser || !a.Can(PermOrganizationDelete) {
		t.Fatalf("access = %+v, %v", a, err)
	}
}

func TestTheLocalSuperuserEntersEveryOrganizationThroughTheBypass(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.CreateOrganization(e.ctx, e.admin, "shop", "Shop", ""); err != nil {
		t.Fatal(err)
	}
	a, err := e.svc.ResolveOrganization(e.ctx, e.admin, Session{AuthMethod: AuthMethodPassword}, "shop")
	if err != nil || !a.ViaSuperuser || !a.Can(PermOrganizationUpdate) {
		t.Fatalf("access = %+v, %v", a, err)
	}
}

func TestOrganizationsOfferedAreTheSessionsRealms(t *testing.T) {
	e := newEnv(t)
	_, sess := e.anaIn()
	if _, err := e.svc.CreateOrganization(e.ctx, e.admin, "bakery", "Bakery", "r-bakery"); err != nil {
		t.Fatal(err)
	}
	orgs, err := e.svc.ListOrganizations(e.ctx, sess)
	if err != nil || len(orgs) != 1 || orgs[0].Slug != "shop" {
		t.Fatalf("orgs = %+v, %v", orgs, err)
	}
}

func TestPermissionImplicationAndWireKeys(t *testing.T) {
	set := NewPermissionSet(PermOrganizationUpdate)
	if !set.Has(PermOrganizationRead) || set.Has(PermOrganizationDelete) || set.Has(PermAuditRead) {
		t.Fatal("implication is wrong")
	}
	if got := PermAPIKeysCreate.WireKey("shop"); got != "shop:biz:apikeys:create" {
		t.Fatalf("wire key = %q", got)
	}
	if got := PermSystemSignin.WireKey("shop"); got != "shop:system:signin" {
		t.Fatalf("system wire key = %q", got)
	}
	keys := fromWireKeys("shop", []string{"shop:biz:apikeys:create", "shop:system:signin", "other:biz:apikeys:read"}, Catalog)
	if len(keys) != 1 || !keys.Has(PermAPIKeysCreate) {
		t.Fatalf("mapped = %v", keys.Slice())
	}
}
