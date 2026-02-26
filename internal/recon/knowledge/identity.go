package knowledge

type IdentityKind int

const (
	IdentityUnknown   IdentityKind = iota
	IdentityNone                   // no credentials sent
	IdentityBootstrap              // server issued a session
	IdentityGuest                  // low privilege authenticated
	IdentityUser                   // normal authenticated
	IdentityElevated               // admin / role based
	IdentityInvalid                // tampered / rejected
)

type Identity struct {
	Name string
	Kind IdentityKind
	Role string

	// Mechanism fingerprint
	CookieNames []string
	AuthScheme  string
	HasCSRF     bool

	// Behavior evidence
	IssuedByServer bool
	Rotates        bool
	Rejected       bool

	Effective bool
	SentCreds bool
}
