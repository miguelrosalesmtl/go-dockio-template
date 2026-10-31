package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ConnectionSettings is the single oidc_settings row: the one døckio connection.
type ConnectionSettings struct {
	Issuer          string
	ClientID        string
	ClientSecretEnc []byte
	Enabled         bool

	// Quick connect fields; all nil for a connection set up by hand.
	ConnectionID    *string
	TenantName      *string
	TenantAddress   *string
	HomeRealm       *string
	ManageURI       *string
	SecretExpiresAt *time.Time
	ConnectedAt     *time.Time
	ConnectedBy     *uuid.UUID
	RevokedAt       *time.Time

	CatalogVersion  *int64
	CatalogSyncedAt *time.Time
	UpdatedAt       time.Time
}

const connectionColumns = `issuer, client_id, client_secret_enc, enabled, connection_id, tenant_name, tenant_address,
	home_realm, manage_uri, secret_expires_at, connected_at, connected_by, revoked_at,
	catalog_version, catalog_synced_at, updated_at`

func scanConnection(r row) (ConnectionSettings, error) {
	var c ConnectionSettings
	err := r.Scan(&c.Issuer, &c.ClientID, &c.ClientSecretEnc, &c.Enabled, &c.ConnectionID, &c.TenantName,
		&c.TenantAddress, &c.HomeRealm, &c.ManageURI, &c.SecretExpiresAt, &c.ConnectedAt, &c.ConnectedBy,
		&c.RevokedAt, &c.CatalogVersion, &c.CatalogSyncedAt, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ConnectionSettings{}, ErrNotConnected
	}
	if err != nil {
		return ConnectionSettings{}, fmt.Errorf("identity: read oidc settings: %w", err)
	}
	return c, nil
}

// GetConnection reads the connection, or ErrNotConnected.
func (r *Repository) GetConnection(ctx context.Context) (ConnectionSettings, error) {
	return scanConnection(r.db.QueryRow(ctx, `SELECT `+connectionColumns+` FROM oidc_settings WHERE id = 1`))
}

// LockConnection reads the connection FOR UPDATE, so two connects or a connect
// and a revocation notice cannot interleave.
func (r *Repository) LockConnection(ctx context.Context) (ConnectionSettings, error) {
	return scanConnection(r.db.QueryRow(ctx, `SELECT `+connectionColumns+` FROM oidc_settings WHERE id = 1 FOR UPDATE`))
}

// SaveConnection writes the connection, replacing whatever was there.
func (r *Repository) SaveConnection(ctx context.Context, c ConnectionSettings) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO oidc_settings (id, issuer, client_id, client_secret_enc, enabled, connection_id, tenant_name,
		     tenant_address, home_realm, manage_uri, secret_expires_at, connected_at, connected_by, revoked_at,
		     catalog_version, catalog_synced_at)
		 VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		 ON CONFLICT (id) DO UPDATE SET
		     issuer = EXCLUDED.issuer, client_id = EXCLUDED.client_id,
		     client_secret_enc = EXCLUDED.client_secret_enc, enabled = EXCLUDED.enabled,
		     connection_id = EXCLUDED.connection_id, tenant_name = EXCLUDED.tenant_name,
		     tenant_address = EXCLUDED.tenant_address, home_realm = EXCLUDED.home_realm,
		     manage_uri = EXCLUDED.manage_uri, secret_expires_at = EXCLUDED.secret_expires_at,
		     connected_at = EXCLUDED.connected_at, connected_by = EXCLUDED.connected_by,
		     revoked_at = EXCLUDED.revoked_at, catalog_version = EXCLUDED.catalog_version,
		     catalog_synced_at = EXCLUDED.catalog_synced_at, updated_at = now()`,
		c.Issuer, c.ClientID, c.ClientSecretEnc, c.Enabled, c.ConnectionID, c.TenantName, c.TenantAddress,
		c.HomeRealm, c.ManageURI, c.SecretExpiresAt, c.ConnectedAt, c.ConnectedBy, c.RevokedAt,
		c.CatalogVersion, c.CatalogSyncedAt,
	)
	if err != nil {
		return fmt.Errorf("identity: save oidc settings: %w", err)
	}
	return nil
}

// DeleteConnection forgets the connection entirely.
func (r *Repository) DeleteConnection(ctx context.Context) error {
	if _, err := r.db.Exec(ctx, `DELETE FROM oidc_settings WHERE id = 1`); err != nil {
		return fmt.Errorf("identity: delete oidc settings: %w", err)
	}
	return nil
}

// SetSigninEnabled turns sign-in with døckio on or off.
func (r *Repository) SetSigninEnabled(ctx context.Context, enabled bool) error {
	tag, err := r.db.Exec(ctx, `UPDATE oidc_settings SET enabled = $1, updated_at = now() WHERE id = 1`, enabled)
	if err != nil {
		return fmt.Errorf("identity: set sign-in enabled: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotConnected
	}
	return nil
}

// MarkRevoked applies a verified revocation notice.
//
// The replay rule is in the WHERE clause: only a notice issued AFTER the last
// connect counts, so a notice for the previous incarnation of a connection cannot
// revoke the one an admin just made. It returns whether a row changed.
func (r *Repository) MarkRevoked(ctx context.Context, connectionID string, issuedAt time.Time) (bool, error) {
	tag, err := r.db.Exec(ctx,
		`UPDATE oidc_settings SET revoked_at = now(), updated_at = now()
		 WHERE id = 1 AND connection_id = $1 AND revoked_at IS NULL AND connected_at < $2`,
		connectionID, issuedAt,
	)
	if err != nil {
		return false, fmt.Errorf("identity: mark connection revoked: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// SetCatalogSynced records the catalog version døckio now holds.
func (r *Repository) SetCatalogSynced(ctx context.Context, version uint64) error {
	_, err := r.db.Exec(ctx,
		`UPDATE oidc_settings SET catalog_version = $1, catalog_synced_at = now() WHERE id = 1`, int64(version)) //nolint:gosec // a catalog version is a small counter
	if err != nil {
		return fmt.Errorf("identity: record catalog sync: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------- connect attempts

// ConnectAttempt is one Quick connect click.
type ConnectAttempt struct {
	ID              uuid.UUID
	CodeVerifierEnc []byte
	UserID          uuid.UUID
	StationURL      string
	PublicURL       string
	Renew           bool
	ConnectionID    *string
}

// CreateConnectAttempt stores an attempt, keyed by the HASH of its state, and
// prunes expired ones on the way in.
func (r *Repository) CreateConnectAttempt(ctx context.Context, stateHash []byte, a ConnectAttempt, ttl time.Duration) error {
	if _, err := r.db.Exec(ctx, `DELETE FROM oidc_connect_attempts WHERE expires_at <= now()`); err != nil {
		return fmt.Errorf("identity: prune connect attempts: %w", err)
	}
	_, err := r.db.Exec(ctx,
		`INSERT INTO oidc_connect_attempts (state_hash, code_verifier_enc, user_id, station_url, public_url,
		                                    renew, connection_id, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8))`,
		stateHash, a.CodeVerifierEnc, a.UserID, a.StationURL, a.PublicURL, a.Renew, a.ConnectionID, ttl.Seconds(),
	)
	if err != nil {
		return fmt.Errorf("identity: create connect attempt: %w", err)
	}
	return nil
}

// TakeConnectAttempt claims an attempt by DELETING it, so it can be used once.
func (r *Repository) TakeConnectAttempt(ctx context.Context, stateHash []byte) (ConnectAttempt, error) {
	var a ConnectAttempt
	err := r.db.QueryRow(ctx,
		`DELETE FROM oidc_connect_attempts WHERE state_hash = $1 AND expires_at > now()
		 RETURNING id, code_verifier_enc, user_id, station_url, public_url, renew, connection_id`,
		stateHash,
	).Scan(&a.ID, &a.CodeVerifierEnc, &a.UserID, &a.StationURL, &a.PublicURL, &a.Renew, &a.ConnectionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ConnectAttempt{}, ErrNotFound
	}
	if err != nil {
		return ConnectAttempt{}, fmt.Errorf("identity: take connect attempt: %w", err)
	}
	return a, nil
}

// ---------------------------------------------------------------- sign-in attempts

// LoginAttempt is one "Continue with døckio" click.
type LoginAttempt struct {
	Nonce           string
	CodeVerifierEnc []byte
	Realm           *string
	ReturnTo        string
}

// CreateLoginAttempt stores an attempt keyed by the hash of its state.
func (r *Repository) CreateLoginAttempt(ctx context.Context, stateHash []byte, a LoginAttempt, ttl time.Duration) error {
	if _, err := r.db.Exec(ctx, `DELETE FROM oidc_login_attempts WHERE expires_at <= now()`); err != nil {
		return fmt.Errorf("identity: prune login attempts: %w", err)
	}
	_, err := r.db.Exec(ctx,
		`INSERT INTO oidc_login_attempts (state_hash, nonce, code_verifier_enc, realm, return_to, expires_at)
		 VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))`,
		stateHash, a.Nonce, a.CodeVerifierEnc, a.Realm, a.ReturnTo, ttl.Seconds(),
	)
	if err != nil {
		return fmt.Errorf("identity: create login attempt: %w", err)
	}
	return nil
}

// TakeLoginAttempt claims an attempt by deleting it.
func (r *Repository) TakeLoginAttempt(ctx context.Context, stateHash []byte) (LoginAttempt, error) {
	var a LoginAttempt
	err := r.db.QueryRow(ctx,
		`DELETE FROM oidc_login_attempts WHERE state_hash = $1 AND expires_at > now()
		 RETURNING nonce, code_verifier_enc, realm, return_to`,
		stateHash,
	).Scan(&a.Nonce, &a.CodeVerifierEnc, &a.Realm, &a.ReturnTo)
	if errors.Is(err, pgx.ErrNoRows) {
		return LoginAttempt{}, ErrNotFound
	}
	if err != nil {
		return LoginAttempt{}, fmt.Errorf("identity: take login attempt: %w", err)
	}
	return a, nil
}

// DeleteExpiredAttempts prunes both attempt tables.
func (r *Repository) DeleteExpiredAttempts(ctx context.Context) (int64, error) {
	var n int64
	for _, table := range []string{"oidc_connect_attempts", "oidc_login_attempts"} {
		tag, err := r.db.Exec(ctx, `DELETE FROM `+table+` WHERE expires_at <= now()`)
		if err != nil {
			return n, fmt.Errorf("identity: prune %s: %w", table, err)
		}
		n += tag.RowsAffected()
	}
	return n, nil
}
