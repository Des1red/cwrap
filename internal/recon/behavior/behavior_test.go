package behavior

import (
	"cwrap/internal/recon/canonicalize"
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/tokens"
	"net/http"
	"net/url"
	"testing"
)

// -------------------------------------------------------
// mock interpreter — minimal implementation for tests
// that need a full Engine
// -------------------------------------------------------

type mockInterpreter struct{}

func (m mockInterpreter) Learn(_ string, _ *http.Response, _ []byte) {}

func (m mockInterpreter) Canonicalize(body []byte, param string) ([]byte, error) {
	return canonicalize.JSON(body, param)
}

func (m mockInterpreter) ClassifyParam(_ *knowledge.Entity, _ string) {}

func testEngine() *Engine {
	k := knowledge.New("http://example.com")
	return New(k, mockInterpreter{}, false)
}

func entWithIdentities(k *knowledge.Knowledge, u string, identities map[string]bool) *knowledge.Entity {
	ent := k.Entity(u)
	for name, sentCreds := range identities {
		id := &knowledge.Identity{Name: name, SentCreds: sentCreds}
		ent.AddIdentity(id)
	}
	return ent
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("mustParseURL(%q): %v", raw, err)
	}
	return u
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// -------------------------------------------------------
// looksLikePathID
// -------------------------------------------------------

func TestLooksLikePathID(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"123", true},
		{"1", true},
		{"0", true},
		{"99999", true},
		{"550e8400-e29b-41d4-a716-446655440000", true},
		{"550E8400-E29B-41D4-A716-446655440000", true},
		{"users", false},
		{"api", false},
		{"posts", false},
		{"", false},
		{"not-a-uuid-format", false},
		{"this-string-is-definitely-way-too-long-to-be-a-path-id-segment", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := looksLikePathID(tt.input); got != tt.want {
				t.Errorf("looksLikePathID(%q) = %v want %v", tt.input, got, tt.want)
			}
		})
	}
}

// -------------------------------------------------------
// pathTemplate
// -------------------------------------------------------

func TestPathTemplate(t *testing.T) {
	tests := []struct {
		rawURL string
		want   string
	}{
		{"http://example.com/api/users/123", "/api/users/{id}"},
		{"http://example.com/api/users/550e8400-e29b-41d4-a716-446655440000", "/api/users/{id}"},
		{"http://example.com/api/users", "/api/users"},
		{"http://example.com/api/users/1/posts/2", "/api/users/{id}/posts/{id}"},
		{"http://example.com/", "/"},
	}

	for _, tt := range tests {
		t.Run(tt.rawURL, func(t *testing.T) {
			u := mustParseURL(t, tt.rawURL)
			got := pathTemplate(u)
			if got != tt.want {
				t.Errorf("pathTemplate(%q) = %q want %q", tt.rawURL, got, tt.want)
			}
		})
	}
}

// -------------------------------------------------------
// discoveryValuesFor
// -------------------------------------------------------

func TestDiscoveryValuesFor(t *testing.T) {
	tests := []struct {
		name       string
		paramName  string
		idLike     bool
		wantValues []string
	}{
		{"id-like param", "user_id", true, []string{"1", "2", "0"}},
		{"page param", "page", false, []string{"1", "2"}},
		{"limit param", "limit", false, []string{"10", "100"}},
		{"offset param", "offset", false, []string{"0", "10"}},
		{"is_ prefix boolean", "is_active", false, []string{"true", "false"}},
		{"enabled boolean", "enabled", false, []string{"true", "false"}},
		{"sort param", "sort", false, []string{"asc", "desc"}},
		{"order_by param", "order_by", false, []string{"asc", "desc"}},
		{"q search param", "q", false, []string{"test", ""}},
		{"search param", "search", false, []string{"test", ""}},
		{"unknown generic", "title", false, []string{"1"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &knowledge.ParamIntel{Name: tt.paramName, IDLike: tt.idLike}
			got := discoveryValuesFor(p)
			if !stringSliceEqual(got, tt.wantValues) {
				t.Errorf("discoveryValuesFor(%q) = %v want %v", tt.paramName, got, tt.wantValues)
			}
		})
	}
}

// -------------------------------------------------------
// methodAllowed
// -------------------------------------------------------

func TestMethodAllowed(t *testing.T) {
	for _, s := range []int{200, 201, 202, 204, 301, 302, 303, 304, 307, 308, 400, 401, 403} {
		if !methodAllowed(s) {
			t.Errorf("methodAllowed(%d) = false want true", s)
		}
	}
	for _, s := range []int{405, 501, 999} {
		if methodAllowed(s) {
			t.Errorf("methodAllowed(%d) = true want false", s)
		}
	}
}

// -------------------------------------------------------
// extractCurrentValue
// -------------------------------------------------------

func TestExtractCurrentValue(t *testing.T) {
	tests := []struct {
		url  string
		key  string
		want string
	}{
		{"http://example.com/api?id=5", "id", "5"},
		{"http://example.com/api?page=2&limit=10", "page", "2"},
		{"http://example.com/api?page=2&limit=10", "limit", "10"},
		{"http://example.com/api", "id", ""},
		{"http://example.com/api?other=1", "id", ""},
	}

	for _, tt := range tests {
		t.Run(tt.url+"["+tt.key+"]", func(t *testing.T) {
			got := extractCurrentValue(tt.url, tt.key)
			if got != tt.want {
				t.Errorf("extractCurrentValue(%q, %q) = %q want %q", tt.url, tt.key, got, tt.want)
			}
		})
	}
}

// -------------------------------------------------------
// isElevatedRole
// -------------------------------------------------------

func TestIsElevatedRole(t *testing.T) {
	for _, r := range []string{"admin", "owner", "root", "superuser", "staff", "moderator", "mod"} {
		if !tokens.IsElevatedRole(r) {
			t.Errorf("isElevatedRole(%q) = false want true", r)
		}
	}
	for _, r := range []string{"member", "user", "viewer", "guest", "readonly"} {
		if tokens.IsElevatedRole(r) {
			t.Errorf("isElevatedRole(%q) = true want false", r)
		}
	}
}

// -------------------------------------------------------
// parseJWT
// -------------------------------------------------------

func TestParseJWT_ValidToken(t *testing.T) {
	// header.{"role":"member","user_id":1,"exp":9999999999}.signature
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoibWVtYmVyIiwidXNlcl9pZCI6MSwiZXhwIjo5OTk5OTk5OTk5fQ.signature"
	claims := tokens.ParseJWT(token)
	if claims == nil {
		t.Fatal("expected claims, got nil")
	}
	if claims["role"] != "member" {
		t.Errorf("expected role=member, got %v", claims["role"])
	}
}

func TestParseJWT_InvalidFormat(t *testing.T) {
	for _, bad := range []string{"not.a.valid.jwt.format.extra", "onlytwoparts.here", ""} {
		if tokens.ParseJWT(bad) != nil {
			t.Errorf("expected nil for malformed token %q", bad)
		}
	}
}

// -------------------------------------------------------
// detectAuthBoundary
// -------------------------------------------------------

func TestDetectAuthBoundary_AuthedSuccessUnauthDenied(t *testing.T) {
	e := testEngine()
	ent := entWithIdentities(e.k, "http://example.com/api", map[string]bool{
		"authed-user": true,
		"anonymous":   false,
	})

	e.detectAuthBoundary(ent, map[string]int{
		"authed-user": 200,
		"anonymous":   401,
	})

	if !ent.SeenSignal(knowledge.SigAuthBoundary) {
		t.Error("expected SigAuthBoundary when authed=200 and unauthed=401")
	}
}

func TestDetectAuthBoundary_403UnauthAlsoTriggers(t *testing.T) {
	e := testEngine()
	ent := entWithIdentities(e.k, "http://example.com/api", map[string]bool{
		"user": true,
		"anon": false,
	})

	e.detectAuthBoundary(ent, map[string]int{"user": 200, "anon": 403})

	if !ent.SeenSignal(knowledge.SigAuthBoundary) {
		t.Error("expected SigAuthBoundary when authed=200 and unauthed=403")
	}
}

func TestDetectAuthBoundary_NoAuthedSuccess(t *testing.T) {
	e := testEngine()
	ent := entWithIdentities(e.k, "http://example.com/api", map[string]bool{
		"authed-user": true,
		"anonymous":   false,
	})

	e.detectAuthBoundary(ent, map[string]int{"authed-user": 403, "anonymous": 401})

	if ent.SeenSignal(knowledge.SigAuthBoundary) {
		t.Error("expected no SigAuthBoundary when authed identity also failed")
	}
}

// -------------------------------------------------------
// detectRoleBoundary
// -------------------------------------------------------

func TestDetectRoleBoundary_AuthedGets403(t *testing.T) {
	e := testEngine()
	ent := entWithIdentities(e.k, "http://example.com/admin", map[string]bool{
		"role-member": true,
	})

	e.detectRoleBoundary(ent, map[string]int{"role-member": 403})

	if !ent.SeenSignal(knowledge.SigRoleBoundary) {
		t.Error("expected SigRoleBoundary when authed identity gets 403")
	}
}

func TestDetectRoleBoundary_UnauthGets403NoTag(t *testing.T) {
	e := testEngine()
	ent := entWithIdentities(e.k, "http://example.com/admin", map[string]bool{
		"anonymous": false,
	})

	e.detectRoleBoundary(ent, map[string]int{"anonymous": 403})

	if ent.SeenSignal(knowledge.SigRoleBoundary) {
		t.Error("expected no SigRoleBoundary when only unauthenticated identity is denied")
	}
}

// -------------------------------------------------------
// analyzeOwnership
// -------------------------------------------------------

func TestAnalyzeOwnership_MixedAccessSetsOwnershipBoundary(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/posts/1")
	ent.AddIdentity(&knowledge.Identity{Name: "user-alice", SentCreds: true})
	ent.AddIdentity(&knowledge.Identity{Name: "user-bob", SentCreds: true})
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
	ent := e.k.Entity("http://example.com/api/posts/1")
	ent.AddIdentity(&knowledge.Identity{Name: "user-alice", SentCreds: true})
	ent.AddIdentity(&knowledge.Identity{Name: "user-bob", SentCreds: true})
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
	ent := e.k.Entity("http://example.com/api/posts/1")
	ent.AddIdentity(&knowledge.Identity{Name: "user-alice", SentCreds: true})
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
// learnProbeImpact
// -------------------------------------------------------

func TestLearnProbeImpact_ChangedFingerprintIncreasesInterest(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/users")
	ent.AddParam("id", knowledge.ParamJSON)
	ent.Params["id"].IDLike = true

	probe := knowledge.Probe{
		URL:      "http://example.com/api/users",
		Method:   "GET",
		AddQuery: map[string]string{"id": "1"},
	}

	e.learnProbeImpact(ent, probe, map[string]string{
		"baseline": "200:aaaa",
		"authed":   "200:bbbb",
	}, "200:aaaa")

	p := ent.Params["id"]
	if p.Interest < 1 {
		t.Error("expected Interest to increase when probe changes behavior")
	}
	if !p.ObservedChanges["input-affects-response"] {
		t.Error("expected input-affects-response change recorded")
	}
}

func TestLearnProbeImpact_SameFingerprintNoChange(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/users")
	ent.AddParam("id", knowledge.ParamJSON)

	probe := knowledge.Probe{
		URL:      "http://example.com/api/users",
		Method:   "GET",
		AddQuery: map[string]string{"id": "1"},
	}

	e.learnProbeImpact(ent, probe, map[string]string{
		"baseline": "200:aaaa",
		"authed":   "200:aaaa",
	}, "200:aaaa")

	if ent.Params["id"].Interest != 0 {
		t.Error("expected no Interest change when fingerprints are identical")
	}
}

func TestLearnProbeImpact_InjectedOnlyParamSkipped(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/users")
	ent.AddParam("injected_param", knowledge.ParamInjected)

	probe := knowledge.Probe{
		URL:      "http://example.com/api/users",
		Method:   "GET",
		AddQuery: map[string]string{"injected_param": "1"},
	}

	e.learnProbeImpact(ent, probe, map[string]string{
		"baseline": "200:aaaa",
		"authed":   "200:bbbb",
	}, "200:aaaa")

	if ent.Params["injected_param"].Interest != 0 {
		t.Error("expected no Interest change for injected-only param")
	}
}
