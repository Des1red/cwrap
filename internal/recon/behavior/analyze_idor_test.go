package behavior

import (
	"cwrap/internal/recon/knowledge"
	"testing"
)

// -------------------------------------------------------
// analyzeIDOR — weak signal (raw fingerprint diff)
// -------------------------------------------------------

func TestAnalyzeIDOR_WeakSignalRawDiffSetsSuspectIDOR(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/posts/1")

	ent.AddIdentity(&knowledge.Identity{
		Name:      "user-alice",
		SentCreds: true,
		Kind:      knowledge.IdentityUser,
	})
	e.identities = append(e.identities, Identity{Name: "user-alice", Synthetic: false})

	ent.AddIdentity(&knowledge.Identity{
		Name:      "user-bob",
		SentCreds: true,
		Kind:      knowledge.IdentityUser,
	})
	e.identities = append(e.identities, Identity{Name: "user-bob", Synthetic: false})

	ent.AddParam("post_id", knowledge.ParamPath)
	p := ent.Params["post_id"]
	p.IDLike = true

	// Same JSON shape for both values, so canonicalize.JSON normalizes
	// them to identical structure — no structural diff, STRONG signal
	// stays off. Raw bytes differ, so rawFPs picks up 2 distinct
	// fingerprints — that's the weak signal's actual evidence.
	responses := map[string]map[string]map[string][]byte{
		"post_id": {
			"1": {
				"user-alice": []byte(`{"id":1,"name":"a"}`),
				"user-bob":   []byte(`{"error":"forbidden"}`),
			},
			"2": {
				"user-alice": []byte(`{"id":2,"name":"b"}`),
			},
		},
	}
	statuses := map[string]map[string]map[string]int{
		"post_id": {
			"1": {"user-alice": 200, "user-bob": 403},
			"2": {"user-alice": 200},
		},
	}

	e.analyzeIDOR(ent, responses, statuses)

	if !p.SuspectIDOR {
		t.Error("expected SuspectIDOR=true from raw fingerprint diff across 2+ values with credDenied")
	}
	if !p.ObservedChanges["idor-raw-diff"] {
		t.Error("expected idor-raw-diff recorded in ObservedChanges")
	}
	if p.PossibleIDOR {
		t.Error("expected PossibleIDOR to remain false — same-shape JSON should not trigger the strong structural-diff signal")
	}
}

func TestAnalyzeIDOR_WeakSignalRequiresCredDenied(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/posts/1")

	ent.AddIdentity(&knowledge.Identity{
		Name:      "user-alice",
		SentCreds: true,
		Kind:      knowledge.IdentityUser,
	})
	e.identities = append(e.identities, Identity{Name: "user-alice", Synthetic: false})

	ent.AddParam("post_id", knowledge.ParamPath)
	p := ent.Params["post_id"]
	p.IDLike = true

	// Two distinct raw bodies (rawFPs >= 2), but nobody was ever denied —
	// credDenied never gets set, so the weak signal must not fire even
	// though the raw-diff count condition alone is satisfied.
	responses := map[string]map[string]map[string][]byte{
		"post_id": {
			"1": {"user-alice": []byte(`{"id":1,"name":"a"}`)},
			"2": {"user-alice": []byte(`{"id":2,"name":"b"}`)},
		},
	}
	statuses := map[string]map[string]map[string]int{
		"post_id": {
			"1": {"user-alice": 200},
			"2": {"user-alice": 200},
		},
	}

	e.analyzeIDOR(ent, responses, statuses)

	if p.SuspectIDOR {
		t.Error("expected no SuspectIDOR when no credentialed identity was ever denied")
	}
}

// -------------------------------------------------------
// analyzeIDOR — skip conditions
// -------------------------------------------------------

func TestAnalyzeIDOR_InjectedOnlyParamSkipped(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/posts")

	ent.AddIdentity(&knowledge.Identity{
		Name:      "user-alice",
		SentCreds: true,
		Kind:      knowledge.IdentityUser,
	})
	e.identities = append(e.identities, Identity{Name: "user-alice", Synthetic: false})

	ent.AddParam("_cwrap_probe", knowledge.ParamInjected)
	p := ent.Params["_cwrap_probe"]
	p.IDLike = true

	responses := map[string]map[string]map[string][]byte{
		"_cwrap_probe": {
			"1": {"user-alice": []byte(`{"id":1}`)},
			"2": {"user-alice": []byte(`{"id":2,"extra":"data"}`)},
		},
	}
	statuses := map[string]map[string]map[string]int{
		"_cwrap_probe": {
			"1": {"user-alice": 200},
			"2": {"user-alice": 200},
		},
	}

	e.analyzeIDOR(ent, responses, statuses)

	if p.PossibleIDOR || p.SuspectIDOR {
		t.Error("expected injected-only param to be skipped entirely by analyzeIDOR")
	}
}

func TestAnalyzeIDOR_PureReflectionParamSkipped(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/search")

	ent.AddIdentity(&knowledge.Identity{
		Name:      "user-alice",
		SentCreds: true,
		Kind:      knowledge.IdentityUser,
	})
	e.identities = append(e.identities, Identity{Name: "user-alice", Synthetic: false})

	ent.AddParam("q", knowledge.ParamQuery)
	p := ent.Params["q"]
	p.IDLike = true
	p.LikelyReflection = true // isPureReflection: true when no other evidence flags are set

	responses := map[string]map[string]map[string][]byte{
		"q": {
			"a": {"user-alice": []byte(`{"query":"a"}`)},
			"b": {"user-alice": []byte(`{"query":"b","results":[1,2,3]}`)},
		},
	}
	statuses := map[string]map[string]map[string]int{
		"q": {
			"a": {"user-alice": 200},
			"b": {"user-alice": 200},
		},
	}

	e.analyzeIDOR(ent, responses, statuses)

	if p.PossibleIDOR || p.SuspectIDOR {
		t.Error("expected pure-reflection param to be skipped entirely by analyzeIDOR")
	}
}

// -------------------------------------------------------
// analyzeIDOR — response-derived suppression
// -------------------------------------------------------

func TestAnalyzeIDOR_ResponseDerivedSuppressedWhenRealInputIDExists(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/users/1")

	ent.AddIdentity(&knowledge.Identity{
		Name:      "user-alice",
		SentCreds: true,
		Kind:      knowledge.IdentityUser,
	})
	e.identities = append(e.identities, Identity{Name: "user-alice", Synthetic: false})

	ent.AddIdentity(&knowledge.Identity{
		Name:      "user-bob",
		SentCreds: true,
		Kind:      knowledge.IdentityUser,
	})
	e.identities = append(e.identities, Identity{Name: "user-bob", Synthetic: false})

	// A real, controllable ID param already exists on this entity —
	// this is what makes the JSON-derived "user_id" field below
	// secondary/supporting evidence rather than a primary IDOR surface.
	ent.AddParam("id", knowledge.ParamPath)
	ent.Params["id"].IDLike = true

	ent.AddParam("user_id", knowledge.ParamJSON)
	p := ent.Params["user_id"]
	p.IDLike = true

	// Same shape of evidence that triggered both signals in the earlier
	// "still detected" test — structural diff AND credDenied both present.
	responses := map[string]map[string]map[string][]byte{
		"user_id": {
			"1": {
				"user-alice": []byte(`{"id":1,"name":"Alice"}`),
				"user-bob":   []byte(`{"error":"forbidden"}`),
			},
			"2": {
				"user-alice": []byte(`{"id":2,"owner":"private","extra":"data"}`),
			},
		},
	}
	statuses := map[string]map[string]map[string]int{
		"user_id": {
			"1": {"user-alice": 200, "user-bob": 403},
			"2": {"user-alice": 200},
		},
	}

	e.analyzeIDOR(ent, responses, statuses)

	if p.PossibleIDOR {
		t.Error("expected PossibleIDOR=false: response-derived param must be suppressed when a real-input ID param exists on the same entity")
	}
	if p.SuspectIDOR {
		t.Error("expected SuspectIDOR=false: response-derived param must be suppressed when a real-input ID param exists on the same entity")
	}
}

// -------------------------------------------------------
// analyzeIDOR — ownership IDOR reachability (fix #1)
// -------------------------------------------------------

func TestAnalyzeIDOR_OwnershipFlagsIDORWithoutTwoDistinctBodies(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/posts/1")

	ent.AddIdentity(&knowledge.Identity{
		Name:      "user-alice",
		SentCreds: true,
		Kind:      knowledge.IdentityUser,
	})
	e.identities = append(e.identities, Identity{Name: "user-alice", Synthetic: false})

	ent.AddParam("post_id", knowledge.ParamPath)
	p := ent.Params["post_id"]
	p.IDLike = true
	// Simulates ownership/object-access evidence already established by
	// analyzeOwnership/analyzeParamBehavior earlier in the probe pipeline —
	// this is the "ownership already proven" case the code comment
	// describes.
	p.OwnershipBoundary = true
	p.LikelyObjectAccess = true

	// Only ONE distinct value was probed with a usable credentialed body,
	// so canonBodies never reaches 2 — this is exactly the condition that
	// used to skip the ownership check entirely via the old loop-level
	// continue.
	responses := map[string]map[string]map[string][]byte{
		"post_id": {
			"1": {"user-alice": []byte(`{"id":1,"owner":"alice"}`)},
		},
	}
	statuses := map[string]map[string]map[string]int{
		"post_id": {
			"1": {"user-alice": 200},
		},
	}

	e.analyzeIDOR(ent, responses, statuses)

	if !p.PossibleIDOR {
		t.Error("expected PossibleIDOR=true via ownership evidence even with fewer than 2 distinct response bodies")
	}
	if !ent.SeenSignal(knowledge.SigPossibleIDOR) {
		t.Error("expected SigPossibleIDOR tag")
	}
}

func TestAnalyzeIDOR_NoOwnershipBoundaryNotFlagged(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/posts/1")

	ent.AddIdentity(&knowledge.Identity{
		Name:      "user-alice",
		SentCreds: true,
		Kind:      knowledge.IdentityUser,
	})
	e.identities = append(e.identities, Identity{Name: "user-alice", Synthetic: false})

	ent.AddParam("post_id", knowledge.ParamPath)
	p := ent.Params["post_id"]
	p.IDLike = true
	// No OwnershipBoundary, no LikelyObjectAccess, no structure-changes —
	// the ownership branch's guard condition should keep this negative.

	responses := map[string]map[string]map[string][]byte{
		"post_id": {
			"1": {"user-alice": []byte(`{"id":1}`)},
		},
	}
	statuses := map[string]map[string]map[string]int{
		"post_id": {
			"1": {"user-alice": 200},
		},
	}

	e.analyzeIDOR(ent, responses, statuses)

	if p.PossibleIDOR {
		t.Error("expected no PossibleIDOR when OwnershipBoundary/LikelyObjectAccess/structure-changes are all absent")
	}
}

func TestAnalyzeIDOR_StrongStructuralDiffStillDetectedWithTwoValues(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/posts/1")

	ent.AddIdentity(&knowledge.Identity{
		Name:      "user-alice",
		SentCreds: true,
		Kind:      knowledge.IdentityUser,
	})
	e.identities = append(e.identities, Identity{Name: "user-alice", Synthetic: false})

	ent.AddIdentity(&knowledge.Identity{
		Name:      "user-bob",
		SentCreds: true,
		Kind:      knowledge.IdentityUser,
	})
	e.identities = append(e.identities, Identity{Name: "user-bob", Synthetic: false})

	ent.AddParam("post_id", knowledge.ParamPath)
	p := ent.Params["post_id"]
	p.IDLike = true

	// value "1": alice succeeds, bob (a different authenticated identity)
	// is denied — this is what sets credDenied.
	// value "2": alice succeeds again, with a structurally different body.
	responses := map[string]map[string]map[string][]byte{
		"post_id": {
			"1": {
				"user-alice": []byte(`{"id":1,"name":"Alice"}`),
				"user-bob":   []byte(`{"error":"forbidden"}`),
			},
			"2": {
				"user-alice": []byte(`{"id":2,"owner":"private","extra":"data"}`),
			},
		},
	}
	statuses := map[string]map[string]map[string]int{
		"post_id": {
			"1": {"user-alice": 200, "user-bob": 403},
			"2": {"user-alice": 200},
		},
	}

	e.analyzeIDOR(ent, responses, statuses)

	if !p.PossibleIDOR {
		t.Error("expected PossibleIDOR=true from structural diff across 2 distinct credentialed bodies plus credDenied evidence")
	}
	if !p.ObservedChanges["idor-structure-diff"] {
		t.Error("expected idor-structure-diff recorded in ObservedChanges")
	}
	if !ent.SeenSignal(knowledge.SigPossibleIDOR) {
		t.Error("expected SigPossibleIDOR tag")
	}
}
