package knowledge

import "time"

type EntityState struct {
	Seen    bool
	Scanned bool

	FirstSeen time.Time
	LastSeen  time.Time

	LastProbe  time.Time
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
}

type ParamIntel struct {
	Name string

	// Where we saw it.
	Sources map[ParamSource]bool

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
	RiskScore         int
	RiskLabel         string
}

type Signals struct {
	Tags map[Signal]bool

	ScoreHint int
}
