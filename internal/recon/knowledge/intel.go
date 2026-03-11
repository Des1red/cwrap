package knowledge

type EntityState struct {
	Seen       bool
	ProbeCount int
}

type HTTPIntel struct {
	// Observed + inferred allowed methods.
	Methods map[string]bool

	// Interesting headers observed (auth, csrf, caching, etc.)
	Headers map[string]bool

	// Optional: set once we know it
	AuthLikely  bool
	CSRFPresent bool
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
}

type JSLeak struct {
	Kind   string // "jwt", "aws_key", "pem", "firebase", "keyword"
	Source string // URL of JS or page
	Key    string // e.g. "apiKey" or "client_secret" if known
	Value  string // redacted by default; full only if enabled
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
