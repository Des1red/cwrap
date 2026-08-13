package behavior

import (
	"cwrap/internal/model"
	"cwrap/internal/recon/knowledge"
	"net/http"
	"strings"
	"testing"
)

// -------------------------------------------------------
// addLiveIdentity
// -------------------------------------------------------

func TestAddLiveIdentity_RegistersNewIdentity(t *testing.T) {
	e := testEngine()

	e.addLiveIdentity("member-uid-2", map[string]string{"session": "abc123"}, "member|2")

	found := false
	for _, id := range e.identities {
		if id.Name == "member-uid-2" {
			found = true
			if id.Synthetic {
				t.Error("expected live identity to be non-synthetic")
			}
		}
	}
	if !found {
		t.Fatal("expected member-uid-2 to be registered in e.identities")
	}

	if !e.knownRoleUIDs["member|2"] {
		t.Error("expected roleUID registered in knownRoleUIDs")
	}

	cookies, ok := e.k.DiscoveredIdentities["member-uid-2"]
	if !ok {
		t.Fatal("expected DiscoveredIdentities entry for member-uid-2")
	}
	if cookies["session"] != "abc123" {
		t.Errorf("expected snapshot cookie session=abc123, got %v", cookies)
	}
}

func TestAddLiveIdentity_DuplicateNameIgnored(t *testing.T) {
	e := testEngine()
	e.addLiveIdentity("member-uid-2", map[string]string{"session": "abc123"}, "member|2")
	countBefore := len(e.identities)

	e.addLiveIdentity("member-uid-2", map[string]string{"session": "different"}, "member|2")

	if len(e.identities) != countBefore {
		t.Errorf("expected no new identity for duplicate name, count changed from %d to %d", countBefore, len(e.identities))
	}
}

func TestAddLiveIdentity_CookieSnapshotIsIndependentCopy(t *testing.T) {
	e := testEngine()
	cookies := map[string]string{"session": "abc123"}
	e.addLiveIdentity("member-uid-2", cookies, "member|2")

	cookies["session"] = "mutated"

	stored := e.k.DiscoveredIdentities["member-uid-2"]
	if stored["session"] != "abc123" {
		t.Errorf("expected stored snapshot unaffected by later mutation of source map, got %q", stored["session"])
	}
}

func TestAddLiveIdentity_ApplyInjectsCookies(t *testing.T) {
	e := testEngine()
	e.addLiveIdentity("member-uid-2", map[string]string{"session": "abc123"}, "member|2")

	var applyFn func(model.Request) model.Request
	for _, id := range e.identities {
		if id.Name == "member-uid-2" {
			applyFn = id.Apply
		}
	}
	if applyFn == nil {
		t.Fatal("expected an Apply function for member-uid-2")
	}

	out := applyFn(model.Request{})

	found := false
	for _, h := range out.Flags.Headers {
		if strings.EqualFold(h.Name, "Cookie") && strings.Contains(h.Value, "session=abc123") {
			found = true
		}
	}
	if !found {
		t.Error("expected Apply to inject a Cookie header containing session=abc123")
	}
}

func TestAddLiveIdentity_RequeuesEntityWithPathParam(t *testing.T) {
	e := testEngine()
	root := e.k.Entity(e.k.Target)

	// "1" is a path-ID-shaped segment — extractPathParams should find it
	// and addLiveIdentity should push a self-probe for this entity under
	// the new identity.
	ent := e.k.Entity("http://example.com/api/users/1")
	ent.State.Seen = true

	e.addLiveIdentity("member-uid-2", map[string]string{"session": "abc123"}, "member|2")

	// Note: this only confirms requeueing happens at all — it does not
	// assert an exact count, since addLiveIdentity's two requeue loops
	// have overlapping trigger conditions (tracked separately as a
	// possible double-probe issue).
	if root.ProbeQueue.Len() == 0 {
		t.Error("expected root's ProbeQueue to gain at least one probe for the path-ID entity")
	}
}

// -------------------------------------------------------
// discoverIdentityFromResponse
// -------------------------------------------------------

// JWT-shaped fixtures: header.payload.signature, payload base64url-encoding
// {"role":"member","user_id":N,"exp":9999999999} or an empty-claims body.
const (
	jwtMemberUID2 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoibWVtYmVyIiwidXNlcl9pZCI6MiwiZXhwIjo5OTk5OTk5OTk5fQ.signature"
	jwtMemberUID3 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoibWVtYmVyIiwidXNlcl9pZCI6MywiZXhwIjo5OTk5OTk5OTk5fQ.signature"
	jwtNoClaims   = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.signature"
)

func respWithSetCookie(cookiePair string) *http.Response {
	h := http.Header{}
	h.Add("Set-Cookie", cookiePair+"; Path=/")
	return &http.Response{StatusCode: 200, Header: h}
}

func TestDiscoverIdentityFromResponse_NewIdentityRegistered(t *testing.T) {
	e := testEngine()
	resp := respWithSetCookie("session=" + jwtMemberUID2)

	e.discoverIdentityFromResponse(resp)

	found := false
	for _, id := range e.identities {
		if id.Name == "member-uid-2" {
			found = true
		}
	}
	if !found {
		t.Error("expected member-uid-2 to be discovered and registered")
	}
	if !e.discoveredIdentities["member|2"] {
		t.Error("expected roleUID recorded in discoveredIdentities")
	}
}

func TestDiscoverIdentityFromResponse_KnownRoleUIDSkipped(t *testing.T) {
	e := testEngine()
	e.knownRoleUIDs["member|2"] = true

	resp := respWithSetCookie("session=" + jwtMemberUID2)
	e.discoverIdentityFromResponse(resp)

	for _, id := range e.identities {
		if id.Name == "member-uid-2" {
			t.Error("expected no new identity when roleUID already in knownRoleUIDs")
		}
	}
}

func TestDiscoverIdentityFromResponse_AlreadyDiscoveredSkipped(t *testing.T) {
	e := testEngine()
	e.discoveredIdentities["member|2"] = true

	resp := respWithSetCookie("session=" + jwtMemberUID2)
	e.discoverIdentityFromResponse(resp)

	for _, id := range e.identities {
		if id.Name == "member-uid-2" {
			t.Error("expected no new identity when roleUID already in discoveredIdentities")
		}
	}
}

func TestDiscoverIdentityFromResponse_NoClaimsNoOp(t *testing.T) {
	e := testEngine()
	resp := respWithSetCookie("session=" + jwtNoClaims)

	e.discoverIdentityFromResponse(resp)

	if len(e.identities) != 0 {
		t.Errorf("expected no identity added for a JWT with no role/user_id claims, got %d", len(e.identities))
	}
}

func TestDiscoverIdentityFromResponse_NonJWTCookieIgnored(t *testing.T) {
	e := testEngine()
	resp := respWithSetCookie("session=plainopaquevalue")

	e.discoverIdentityFromResponse(resp)

	if len(e.identities) != 0 {
		t.Errorf("expected no identity added for a non-JWT cookie value, got %d", len(e.identities))
	}
}

// -------------------------------------------------------
// captureSession
// -------------------------------------------------------

func TestCaptureSession_SyntheticIdentitySkipped(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api")

	e.captureSession(ent, Identity{Name: "anonymous", Synthetic: true}, respWithSetCookie("x=y"), "http://example.com")

	if ent.SessionUsed || ent.SessionIssued || len(ent.SessionCookies) > 0 {
		t.Error("expected no session state changes for a synthetic identity")
	}
}

func TestCaptureSession_UnknownIdentitySkipped(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api")
	// "ghost" was never registered via AddIdentity — id lookup returns nil.

	e.captureSession(ent, Identity{Name: "ghost", Synthetic: false}, respWithSetCookie("x=y"), "http://example.com")

	if len(ent.SessionCookies) > 0 {
		t.Error("expected no session state changes for an identity not present on the entity")
	}
}

func TestCaptureSession_RejectedIdentitySkipped(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api")
	ent.AddIdentity(&knowledge.Identity{Name: "compromised", Rejected: true})

	e.captureSession(ent, Identity{Name: "compromised", Synthetic: false}, respWithSetCookie("x=y"), "http://example.com")

	if len(ent.SessionCookies) > 0 {
		t.Error("expected no session state changes for a rejected identity")
	}
}

func TestCaptureSession_NonLiveSessionTriggersIdentityDiscovery(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api")
	ent.AddIdentity(&knowledge.Identity{Name: "member-uid-2", Rejected: false, SentCreds: true})

	resp := respWithSetCookie("session=" + jwtMemberUID3)

	e.captureSession(ent, Identity{Name: "member-uid-2", Synthetic: false}, resp, "http://example.com")

	found := false
	for _, id := range e.identities {
		if id.Name == "member-uid-3" {
			found = true
		}
	}
	if !found {
		t.Error("expected captureSession to delegate to discoverIdentityFromResponse for a non-LiveSession identity")
	}
	// This path must never touch session persistence fields — that's the
	// LiveSession branch's job only.
	if ent.SessionUsed || ent.SessionIssued || len(ent.SessionCookies) > 0 {
		t.Error("expected no session-persistence fields touched on the non-LiveSession path")
	}
}

// -------------------------------------------------------
// corruptJWTCookies
// -------------------------------------------------------

func TestCorruptJWTCookies_JWTValueCorrupted(t *testing.T) {
	in := map[string]string{"session": jwtMemberUID2}

	out, changed := corruptJWTCookies(in)

	if !changed {
		t.Fatal("expected changed=true for a JWT-shaped cookie value")
	}
	if out["session"] == jwtMemberUID2 {
		t.Error("expected the JWT cookie value to be corrupted, got unchanged value")
	}
}

func TestCorruptJWTCookies_NonJWTValueUnchanged(t *testing.T) {
	in := map[string]string{"session": "plainopaquevalue"}

	out, changed := corruptJWTCookies(in)

	if changed {
		t.Error("expected changed=false when no cookie value looks like a JWT")
	}
	if out["session"] != "plainopaquevalue" {
		t.Errorf("expected non-JWT value left untouched, got %q", out["session"])
	}
}

func TestCorruptJWTCookies_MixedCookiesOnlyJWTCorrupted(t *testing.T) {
	in := map[string]string{
		"session": jwtMemberUID2,
		"theme":   "dark",
	}

	out, changed := corruptJWTCookies(in)

	if !changed {
		t.Fatal("expected changed=true when at least one cookie is JWT-shaped")
	}
	if out["theme"] != "dark" {
		t.Errorf("expected non-JWT cookie left untouched, got %q", out["theme"])
	}
	if out["session"] == jwtMemberUID2 {
		t.Error("expected JWT cookie corrupted")
	}
}

// -------------------------------------------------------
// ensureCorruptedCookieIdentity
// -------------------------------------------------------

func TestEnsureCorruptedCookieIdentity_AddsIdentityWhenJWTPresent(t *testing.T) {
	e := testEngine()
	base := model.Request{
		URL: "http://example.com",
		Flags: model.Flags{
			Headers: []model.Header{{Name: "Cookie", Value: "session=" + jwtMemberUID2}},
		},
	}

	e.ensureCorruptedCookieIdentity(base)

	found := false
	for _, id := range e.identities {
		if id.Name == knowledge.CorruptedCookieToken {
			found = true
			if !id.Synthetic {
				t.Error("expected corrupted-cookie identity to be synthetic")
			}
		}
	}
	if !found {
		t.Error("expected a CorruptedCookieToken identity to be registered")
	}
}

func TestEnsureCorruptedCookieIdentity_NoOpWithoutJWTCookie(t *testing.T) {
	e := testEngine()
	base := model.Request{
		URL: "http://example.com",
		Flags: model.Flags{
			Headers: []model.Header{{Name: "Cookie", Value: "theme=dark"}},
		},
	}

	e.ensureCorruptedCookieIdentity(base)

	for _, id := range e.identities {
		if id.Name == knowledge.CorruptedCookieToken {
			t.Error("expected no CorruptedCookieToken identity when no JWT cookie is present")
		}
	}
}

func TestEnsureCorruptedCookieIdentity_SkipsIfAlreadyPresent(t *testing.T) {
	e := testEngine()
	e.identities = append(e.identities, Identity{Name: knowledge.CorruptedCookieToken, Synthetic: true})

	base := model.Request{
		URL: "http://example.com",
		Flags: model.Flags{
			Headers: []model.Header{{Name: "Cookie", Value: "session=" + jwtMemberUID2}},
		},
	}

	e.ensureCorruptedCookieIdentity(base)

	count := 0
	for _, id := range e.identities {
		if id.Name == knowledge.CorruptedCookieToken {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 CorruptedCookieToken identity, got %d", count)
	}
}

func TestEnsureCorruptedCookieIdentity_RequeuesSeenEntities(t *testing.T) {
	e := testEngine()
	root := e.k.Entity(e.k.Target)

	ent := e.k.Entity("http://example.com/api/data")
	ent.State.Seen = true

	base := model.Request{
		URL: "http://example.com",
		Flags: model.Flags{
			Headers: []model.Header{{Name: "Cookie", Value: "session=" + jwtMemberUID2}},
		},
	}

	e.ensureCorruptedCookieIdentity(base)

	if root.ProbeQueue.Len() == 0 {
		t.Error("expected a seen, non-static, non-terminator entity to be requeued under the new identity")
	}
}
