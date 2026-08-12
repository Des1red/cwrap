package behavior

import (
	"cwrap/internal/recon/knowledge"
	"testing"
)

// -------------------------------------------------------
// analyzeParamBehavior — reflection / object access / enumeration
// -------------------------------------------------------

func TestAnalyzeParamBehavior_StableStructureSetsReflection(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/search")

	ent.AddIdentity(&knowledge.Identity{Name: "user-alice", SentCreds: true, Kind: knowledge.IdentityUser})
	e.identities = append(e.identities, Identity{Name: "user-alice", Synthetic: false})

	ent.AddParam("q", knowledge.ParamQuery)
	p := ent.Params["q"]

	// Same JSON shape, different leaf values — canonicalize.JSON collapses
	// both to an identical normalized structure, so allSame stays true.
	responses := map[string]map[string]map[string][]byte{
		"q": {
			"a": {"user-alice": []byte(`{"id":1}`)},
			"b": {"user-alice": []byte(`{"id":2}`)},
		},
	}

	e.analyzeParamBehavior(ent, responses)

	if !p.LikelyReflection {
		t.Error("expected LikelyReflection=true for stable structure across values")
	}
	if !p.ObservedChanges["stable-structure"] {
		t.Error("expected stable-structure recorded in ObservedChanges")
	}
	if p.Interest != 1 {
		t.Errorf("expected Interest=1, got %d", p.Interest)
	}
}

func TestAnalyzeParamBehavior_StructuralDiffSetsLikelyObjectAccess(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/posts")

	ent.AddIdentity(&knowledge.Identity{Name: "user-alice", SentCreds: true, Kind: knowledge.IdentityUser})
	e.identities = append(e.identities, Identity{Name: "user-alice", Synthetic: false})

	ent.AddParam("id", knowledge.ParamQuery)
	p := ent.Params["id"]

	// Different key sets — canonicalize.JSON preserves structure, so this
	// produces two genuinely different normalized shapes.
	responses := map[string]map[string]map[string][]byte{
		"id": {
			"1": {"user-alice": []byte(`{"a":1}`)},
			"2": {"user-alice": []byte(`{"a":1,"secret":"x"}`)},
		},
	}

	e.analyzeParamBehavior(ent, responses)

	if !p.LikelyObjectAccess {
		t.Error("expected LikelyObjectAccess=true for structural diff")
	}
	if p.LikelyReflection {
		t.Error("expected LikelyReflection=false once structural diff is found")
	}
	if !p.ObservedChanges["structure-changes"] {
		t.Error("expected structure-changes recorded")
	}
	if p.Enumerable {
		t.Error("expected Enumerable=false with only 2 unique structures")
	}
	if p.Interest != 2 {
		t.Errorf("expected Interest=2 (object access only), got %d", p.Interest)
	}
}

func TestAnalyzeParamBehavior_ThreeUniqueStructuresSetsEnumerable(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/posts")

	ent.AddIdentity(&knowledge.Identity{Name: "user-alice", SentCreds: true, Kind: knowledge.IdentityUser})
	e.identities = append(e.identities, Identity{Name: "user-alice", Synthetic: false})

	ent.AddParam("id", knowledge.ParamQuery)
	p := ent.Params["id"]

	responses := map[string]map[string]map[string][]byte{
		"id": {
			"1": {"user-alice": []byte(`{"a":1}`)},
			"2": {"user-alice": []byte(`{"a":1,"b":2}`)},
			"3": {"user-alice": []byte(`{"a":1,"b":2,"c":3}`)},
		},
	}

	e.analyzeParamBehavior(ent, responses)

	if !p.Enumerable {
		t.Error("expected Enumerable=true with 3 unique structures")
	}
	if !p.ObservedChanges["enumerable-structure-space"] {
		t.Error("expected enumerable-structure-space recorded")
	}
	if p.Interest != 4 {
		t.Errorf("expected Interest=4 (object access +2, enumerable +2), got %d", p.Interest)
	}
}

func TestAnalyzeParamBehavior_CanonicalizeErrorSetsObjectAccess(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/blob")

	ent.AddIdentity(&knowledge.Identity{Name: "user-alice", SentCreds: true, Kind: knowledge.IdentityUser})
	e.identities = append(e.identities, Identity{Name: "user-alice", Synthetic: false})

	ent.AddParam("token", knowledge.ParamQuery)
	p := ent.Params["token"]

	// Both bodies are invalid JSON, so regardless of map iteration order
	// the first one processed triggers Canonicalize's error path.
	// Caveat: this assumes canonicalize.JSON returns a non-nil error for
	// malformed input (consistent with a json.Unmarshal-based implementation)
	// — not independently verified against canonicalize's source in this pass.
	responses := map[string]map[string]map[string][]byte{
		"token": {
			"1": {"user-alice": []byte("not json at all")},
			"2": {"user-alice": []byte("also not json")},
		},
	}

	e.analyzeParamBehavior(ent, responses)

	if !p.LikelyObjectAccess {
		t.Error("expected LikelyObjectAccess=true when Canonicalize errors (opaque format)")
	}
	if !p.ObservedChanges["format-opaque"] {
		t.Error("expected format-opaque recorded")
	}
	if p.Interest != 2 {
		t.Errorf("expected Interest=2, got %d", p.Interest)
	}
}

func TestAnalyzeParamBehavior_FewerThanTwoValuesSkipped(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/posts")

	ent.AddIdentity(&knowledge.Identity{Name: "user-alice", SentCreds: true, Kind: knowledge.IdentityUser})
	e.identities = append(e.identities, Identity{Name: "user-alice", Synthetic: false})

	ent.AddParam("id", knowledge.ParamQuery)
	p := ent.Params["id"]

	responses := map[string]map[string]map[string][]byte{
		"id": {
			"1": {"user-alice": []byte(`{"a":1}`)},
		},
	}

	e.analyzeParamBehavior(ent, responses)

	if p.LikelyReflection || p.LikelyObjectAccess || p.Enumerable {
		t.Error("expected no flags set with only 1 probed value")
	}
}

func TestAnalyzeParamBehavior_InjectedOnlyParamSkipped(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/posts")

	ent.AddIdentity(&knowledge.Identity{Name: "user-alice", SentCreds: true, Kind: knowledge.IdentityUser})
	e.identities = append(e.identities, Identity{Name: "user-alice", Synthetic: false})

	ent.AddParam("_cwrap_probe", knowledge.ParamInjected)
	p := ent.Params["_cwrap_probe"]

	responses := map[string]map[string]map[string][]byte{
		"_cwrap_probe": {
			"1": {"user-alice": []byte(`{"a":1}`)},
			"2": {"user-alice": []byte(`{"a":1,"b":2}`)},
		},
	}

	e.analyzeParamBehavior(ent, responses)

	if p.LikelyReflection || p.LikelyObjectAccess {
		t.Error("expected injected-only param to be skipped entirely")
	}
}

func TestAnalyzeParamBehavior_StrongEvidenceSuppressesReflectionFlag(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/posts")

	ent.AddIdentity(&knowledge.Identity{Name: "user-alice", SentCreds: true, Kind: knowledge.IdentityUser})
	e.identities = append(e.identities, Identity{Name: "user-alice", Synthetic: false})

	ent.AddParam("id", knowledge.ParamQuery)
	p := ent.Params["id"]
	p.ObservedChanges = map[string]bool{}
	// Pre-existing strong evidence from an earlier analyzer pass in the
	// real pipeline (e.g. analyzeAuthBoundary already ran on this param).
	p.AuthBoundary = true

	responses := map[string]map[string]map[string][]byte{
		"id": {
			"1": {"user-alice": []byte(`{"a":1}`)},
			"2": {"user-alice": []byte(`{"a":2}`)},
		},
	}

	e.analyzeParamBehavior(ent, responses)

	if p.LikelyReflection {
		t.Error("expected LikelyReflection to stay false when strong evidence already exists")
	}
	if p.ObservedChanges["stable-structure"] {
		t.Error("expected stable-structure not recorded when suppressed by strong evidence")
	}
	if p.Interest != 0 {
		t.Errorf("expected Interest unchanged at 0, got %d", p.Interest)
	}
}
