package behavior

import (
	"cwrap/internal/recon/knowledge"
	"testing"
)

// -------------------------------------------------------
// analyzeOwnership
// -------------------------------------------------------

func TestAnalyzeOwnership_MixedAccessSetsOwnershipBoundary(t *testing.T) {
	e := testEngine()
	ent := entWithIdentities(e, "http://example.com/api/posts/1", map[string]bool{
		"user-alice": true,
		"user-bob":   true,
	})

	ent.AddParam("post_id", knowledge.ParamPath)
	ent.Params["post_id"].IDLike = true

	statuses := map[string]map[string]map[string]int{
		"post_id": {"1": {"user-alice": 200, "user-bob": 403}},
	}

	e.analyzeOwnership(ent, statuses)

	if !ent.Params["post_id"].OwnershipBoundary {
		t.Error("expected OwnershipBoundary=true when one identity succeeds and another fails")
	}
	if !ent.SeenSignal(knowledge.SigObjectOwnership) {
		t.Error("expected SigObjectOwnership signal")
	}
}

func TestAnalyzeOwnership_BothSucceedNoOwnershipBoundary(t *testing.T) {
	e := testEngine()
	ent := entWithIdentities(e, "http://example.com/api/posts/1", map[string]bool{
		"user-alice": true,
		"user-bob":   true,
	})

	ent.AddParam("post_id", knowledge.ParamPath)
	ent.Params["post_id"].IDLike = true

	statuses := map[string]map[string]map[string]int{
		"post_id": {"1": {"user-alice": 200, "user-bob": 200}},
	}

	e.analyzeOwnership(ent, statuses)

	if ent.Params["post_id"].OwnershipBoundary {
		t.Error("expected no OwnershipBoundary when both identities succeed")
	}
}

func TestAnalyzeOwnership_OnlyOneAuthIdentitySkipped(t *testing.T) {
	e := testEngine()
	ent := entWithIdentities(e, "http://example.com/api/posts/1", map[string]bool{
		"user-alice": true,
	})

	ent.AddParam("post_id", knowledge.ParamPath)
	ent.Params["post_id"].IDLike = true

	statuses := map[string]map[string]map[string]int{
		"post_id": {"1": {"user-alice": 200}},
	}

	e.analyzeOwnership(ent, statuses)

	if ent.Params["post_id"].OwnershipBoundary {
		t.Error("expected no OwnershipBoundary with only one authed identity")
	}
}

// -------------------------------------------------------
// analyzeObjectAccessSurface — single-identity mixed access
// -------------------------------------------------------

func TestAnalyzeObjectAccessSurface_SameIdentityMixedAccessSetsSuspectIDOR(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/posts")

	ent.AddIdentity(&knowledge.Identity{Name: "user-alice", SentCreds: true, Kind: knowledge.IdentityUser})
	e.identities = append(e.identities, Identity{Name: "user-alice", Synthetic: false})

	ent.AddParam("post_id", knowledge.ParamQuery)
	p := ent.Params["post_id"]
	p.IDLike = true

	// Same identity: succeeds on value "1", denied on value "2" — this is
	// the single-identity inconsistency signal, distinct from cross-identity
	// ownership comparison.
	statuses := map[string]map[string]map[string]int{
		"post_id": {
			"1": {"user-alice": 200},
			"2": {"user-alice": 403},
		},
	}

	e.analyzeObjectAccessSurface(ent, statuses)

	if !p.LikelyObjectAccess {
		t.Error("expected LikelyObjectAccess=true")
	}
	if !p.AuthBoundary {
		t.Error("expected AuthBoundary=true")
	}
	if !p.SuspectIDOR {
		t.Error("expected SuspectIDOR=true")
	}
	if !p.ObservedChanges["single-identity-object-access-control"] {
		t.Error("expected single-identity-object-access-control recorded")
	}
	if p.Interest != 2 {
		t.Errorf("expected Interest=2, got %d", p.Interest)
	}
}

func TestAnalyzeObjectAccessSurface_ConsistentAccessNoFlag(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/posts")

	ent.AddIdentity(&knowledge.Identity{Name: "user-alice", SentCreds: true, Kind: knowledge.IdentityUser})
	e.identities = append(e.identities, Identity{Name: "user-alice", Synthetic: false})

	ent.AddParam("post_id", knowledge.ParamQuery)
	p := ent.Params["post_id"]
	p.IDLike = true

	statuses := map[string]map[string]map[string]int{
		"post_id": {
			"1": {"user-alice": 200},
			"2": {"user-alice": 200},
		},
	}

	e.analyzeObjectAccessSurface(ent, statuses)

	if p.LikelyObjectAccess || p.SuspectIDOR {
		t.Error("expected no flags when the identity is never denied")
	}
}

func TestAnalyzeObjectAccessSurface_NotIDLikeSkipped(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/posts")

	ent.AddIdentity(&knowledge.Identity{Name: "user-alice", SentCreds: true, Kind: knowledge.IdentityUser})
	e.identities = append(e.identities, Identity{Name: "user-alice", Synthetic: false})

	ent.AddParam("filter", knowledge.ParamQuery)
	p := ent.Params["filter"]
	p.IDLike = false

	statuses := map[string]map[string]map[string]int{
		"filter": {
			"1": {"user-alice": 200},
			"2": {"user-alice": 403},
		},
	}

	e.analyzeObjectAccessSurface(ent, statuses)

	if p.LikelyObjectAccess || p.SuspectIDOR {
		t.Error("expected non-IDLike param to be skipped regardless of mixed statuses")
	}
}

func TestAnalyzeObjectAccessSurface_ResponseDerivedParamSkipped(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/posts")

	ent.AddIdentity(&knowledge.Identity{Name: "user-alice", SentCreds: true, Kind: knowledge.IdentityUser})
	e.identities = append(e.identities, Identity{Name: "user-alice", Synthetic: false})

	ent.AddParam("owner_id", knowledge.ParamJSON)
	p := ent.Params["owner_id"]
	p.IDLike = true

	statuses := map[string]map[string]map[string]int{
		"owner_id": {
			"1": {"user-alice": 200},
			"2": {"user-alice": 403},
		},
	}

	e.analyzeObjectAccessSurface(ent, statuses)

	if p.LikelyObjectAccess || p.SuspectIDOR {
		t.Error("expected JSON-only (response-derived) param to be skipped — only real input sources qualify")
	}
}

func TestAnalyzeObjectAccessSurface_NonComparableIdentityIgnored(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/posts")

	// anonymous never sent credentials — isComparableIdentity excludes it.
	ent.AddIdentity(&knowledge.Identity{Name: "anonymous", SentCreds: false, Kind: knowledge.IdentityNone})
	e.identities = append(e.identities, Identity{Name: "anonymous", Synthetic: true})

	ent.AddParam("post_id", knowledge.ParamQuery)
	p := ent.Params["post_id"]
	p.IDLike = true

	statuses := map[string]map[string]map[string]int{
		"post_id": {
			"1": {"anonymous": 200},
			"2": {"anonymous": 403},
		},
	}

	e.analyzeObjectAccessSurface(ent, statuses)

	if p.LikelyObjectAccess || p.SuspectIDOR {
		t.Error("expected non-comparable (uncredentialed) identity's mixed status to be ignored")
	}
}
