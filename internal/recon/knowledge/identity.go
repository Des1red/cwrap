package knowledge

type IdentityKind int

const (
	IdentityUnknown   IdentityKind = iota
	IdentityNone                   // no credentials sent
	IdentityBootstrap              // server issued a session
	IdentityUser                   // normal authenticated
	IdentityElevated               // admin / role based
	IdentityInvalid                // tampered / rejected
)

const (
	IdentityTagCreds       = "creds"
	IdentityTagRejected    = "rejected"
	IdentityTagIssuedToken = "issued-token"
	IdentityTagEffective   = "effective"

	IdentityTagCSRF           = "csrf"
	IdentityTagCSRFToken      = "csrf-token"
	IdentityTagCSRFHeader     = "csrf-header"
	IdentityTagCSRFCookieName = "csrf-cookie"
)

type Identity struct {
	Name     string
	Kind     IdentityKind
	Role     string
	UserID   string
	Expiry   string
	TokenJTI string

	// Mechanism fingerprint
	CookieNames []string
	AuthScheme  string

	HasCSRF        bool
	CSRFToken      string
	CSRFHeader     string // e.g. "X-CSRF-Token" — which header to send it back in
	CSRFCookieName string

	// Behavior evidence
	IssuedByServer bool
	Rejected       bool
	Effective      bool
	SentCreds      bool
}
