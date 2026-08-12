package knowledge

type EntityState struct {
	Seen                  bool
	ProbeCount            int
	MethodProbed          bool
	DiscoveryProbed       bool
	PathIDProbed          bool
	IsPathVariant         bool
	IsParamVariant        bool
	IsSPAFallback         bool
	OrganicallyDiscovered bool
	JSAnalyzed            bool
}

type HTTPIntel struct {
	// Observed + inferred allowed methods.
	Methods map[string]bool

	// Interesting headers observed (auth, csrf, caching, etc.)
	Headers map[string]bool

	// Optional: set once we know it
	AuthLikely  bool
	CSRFPresent bool

	// AuthScheme is the authentication scheme advertised by a
	// WWW-Authenticate challenge (e.g. "bearer", "basic", "digest"),
	// lowercased. Empty if the server never sent a challenge — most APIs
	// using bearer tokens don't bother, so absence isn't itself meaningful,
	// but presence tells you which attack surface applies (credential
	// brute-forcing for Basic, JWT tampering for Bearer, nonce/replay
	// analysis for Digest).
	AuthScheme string

	// CORS evidence. CORSPermissive is true when the response allows
	// credentialed cross-origin requests from any origin — either a
	// wildcard Access-Control-Allow-Origin combined with
	// Access-Control-Allow-Credentials: true (invalid per spec but some
	// servers still send it), or an Allow-Origin that reflects the
	// request's Origin header verbatim while allowing credentials (the
	// dangerous case: any origin can make authenticated requests).
	// CORSOrigin holds the observed Allow-Origin value as evidence.
	CORSPermissive bool
	CORSOrigin     string

	// MissingSecurityHeaders lists hardening headers absent from this
	// response (e.g. "Content-Security-Policy", "X-Frame-Options").
	// Populated only where absence is meaningful — see httpintel's
	// gating logic, not evaluated unconditionally on every response.
	MissingSecurityHeaders []string

	// FrameAncestors holds the raw value of CSP's frame-ancestors
	// directive when present, as evidence for SigPermissiveFrameAncestors.
	FrameAncestors string

	Tech map[string]string // Server, X-Powered-By, X-Generator, etc.
}

type ContentIntel struct {
	// Observed Content-Types (mime -> count)
	MIMEs map[string]int

	// Observed statuses (status -> count)
	Statuses map[int]int

	// Simple content hints
	LooksLikeHTML bool
	LooksLikeJSON bool
	LooksLikeXML  bool

	JSFindings  map[string]int  // kind -> count (jwt/aws_key/pem/firebase/keyword)
	JSLeaks     []JSLeak        // optional evidence (redacted unless enabled)
	SeenJSLeaks map[string]bool // to avoid dupes in JS leaks

	JSHTTPFlows     []JSHTTPFlow
	SeenJSHTTPFlows map[string]bool
}

type JSLeak struct {
	Kind   string // "jwt", "aws_key", "pem", "firebase", "keyword"
	Source string // URL of JS or page
	Key    string // e.g. "apiKey" or "client_secret" if known
	Value  string // redacted by default; full only if enabled
}

type JSHTTPFlow struct {
	Source string

	Function string
	Sink     string

	URLSource    string
	MethodSource string

	ResolvedURL    string
	ResolvedMethod string

	DynamicURL    bool
	DynamicMethod bool

	Confidence string
}

type ParamIntel struct {
	Name string

	// Where we saw it.
	Sources         map[ParamSource]bool
	DiscoveryReason string
	// Optional heuristics:
	IDLike    bool
	TokenLike bool
	DebugLike bool

	// mutation evidence
	ObservedChanges    map[string]bool
	LikelyReflection   bool
	LikelyObjectAccess bool
	// evidence of sequential object space
	Enumerable        bool
	AuthBoundary      bool // access sometimes denied (auth wall exists)
	OwnershipBoundary bool // different objects per identity (idor surface)
	PossibleIDOR      bool
	SuspectIDOR       bool
	IdentityAccess    map[string]int // identity -> success count (200s)
	IdentityDenied    map[string]int // identity -> denied count (401/403)
	Interest          int            // increases when mutations cause behavior diffs
}

type Signals struct {
	Tags map[Signal]bool

	ScoreHint int
}
