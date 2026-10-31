package identity

import "errors"

// Sentinel errors. The server package maps each to one HTTP status in exactly one
// place (response.go), so the service layer never thinks about HTTP.
var (
	// ErrNotFound covers both "does not exist" and "exists but you may not see
	// it". Distinguishing the two would let a stranger enumerate organizations.
	ErrNotFound = errors.New("identity: not found")

	// ErrInvalidCredentials is a failed superuser sign-in. Deliberately vague.
	ErrInvalidCredentials = errors.New("identity: invalid credentials")

	// ErrUnauthenticated means no valid session or API key was presented.
	ErrUnauthenticated = errors.New("identity: unauthenticated")

	// ErrForbidden means authenticated, but lacking the permission.
	ErrForbidden = errors.New("identity: forbidden")

	ErrSlugTaken  = errors.New("identity: organization slug already taken")
	ErrRealmTaken = errors.New("identity: another organization already uses that døckio realm")
	ErrEmailTaken = errors.New("identity: a superuser with that email already exists")

	// ErrEscalation is an attempt to grant a permission the caller does not hold.
	ErrEscalation = errors.New("identity: you cannot grant a permission you do not hold")

	ErrRateLimited = errors.New("identity: too many attempts")
	ErrValidation  = errors.New("identity: validation failed")

	// ErrDockioUnavailable means døckio could not be asked, and the last answer
	// is too old to reuse. Requests that need døckio's answer fail CLOSED.
	ErrDockioUnavailable = errors.New("identity: døckio is unavailable")

	// ErrNotConnected means there is no døckio connection yet.
	ErrNotConnected = errors.New("identity: the application is not connected to døckio")

	// ErrConnectNotSupported means the døckio station cannot connect in one click.
	ErrConnectNotSupported = errors.New("identity: this døckio cannot connect in one click -- set it up by hand")

	// ErrInvalidNotice is a revocation notice that fails verification. It changes
	// nothing and is answered 400.
	ErrInvalidNotice = errors.New("identity: invalid revocation notice")
)

// FlowError is a failure of a browser round trip through døckio -- sign-in or
// Quick connect. Its Code is what the front end receives in the redirect
// (?error=<code> or ?connect_error=<code>): a stable, secret-free identifier the
// front end maps to plain words.
type FlowError struct {
	Code string
	err  error // the detail, for logs only; never put in a URL
}

func (e *FlowError) Error() string {
	if e.err != nil {
		return "identity: " + e.Code + ": " + e.err.Error()
	}
	return "identity: " + e.Code
}

func (e *FlowError) Unwrap() error { return e.err }

func flowError(code string, err error) error { return &FlowError{Code: code, err: err} }

// Flow error codes. docs/dockio.md lists what the front end should say for each.
const (
	// Sign-in.
	CodeSigninUnavailable  = "signin_unavailable"  // no usable connection, or sign-in is off
	CodeInvalidState       = "invalid_state"       // cookie/state mismatch, reused or expired attempt
	CodeAccessDenied       = "access_denied"       // the person cancelled, or døckio refused them
	CodeSigninExpired      = "signin_expired"      // the code was refused: try again
	CodeConnectionExpired  = "connection_expired"  // the client secret has expired
	CodeInvalidToken       = "invalid_token"       // the id token failed verification
	CodeWrongRealm         = "wrong_realm"         // signed in to another realm than asked
	CodeAccountDeactivated = "account_deactivated" // the application deactivated this user
	CodeDockioUnavailable  = "dockio_unavailable"  // døckio could not be reached

	// Quick connect.
	CodeConnectCancelled    = "connect_cancelled"     // cancelled in døckio
	CodeConnectExpired      = "connect_expired"       // the connect code was refused
	CodeConnectForbidden    = "connect_forbidden"     // no longer allowed to change sign-in
	CodeConnectOtherTenant  = "connect_other_tenant"  // another tenant, while organizations use this one
	CodeConnectInvalidGrant = "connect_invalid_grant" // the grant failed validation
)

func isNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

// validationError carries a human-readable reason and matches ErrValidation.
type validationError struct{ msg string }

func (e validationError) Error() string { return e.msg }
func (e validationError) Is(target error) bool {
	return target == ErrValidation
}

func invalid(msg string) error { return validationError{msg: msg} }
