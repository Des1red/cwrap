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
	HasCSRF     bool

	// Behavior evidence
	IssuedByServer bool
	Rejected       bool
	Effective      bool
	SentCreds      bool
}
