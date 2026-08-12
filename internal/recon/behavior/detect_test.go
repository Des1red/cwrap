package behavior

import (
	"cwrap/internal/recon/knowledge"
	"testing"
)

// -------------------------------------------------------
// detectAuthBoundary
// -------------------------------------------------------

func TestDetectAuthBoundary_AuthedSuccessUnauthDenied(t *testing.T) {
	e := testEngine()
	ent := entWithIdentities(e, "http://example.com/api", map[string]bool{
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
	ent := entWithIdentities(e, "http://example.com/api", map[string]bool{
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
	ent := entWithIdentities(e, "http://example.com/api", map[string]bool{
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
	ent := entWithIdentities(e, "http://example.com/admin", map[string]bool{
		"role-member": true,
	})

	e.detectRoleBoundary(ent, map[string]int{"role-member": 403})

	if !ent.SeenSignal(knowledge.SigRoleBoundary) {
		t.Error("expected SigRoleBoundary when authed identity gets 403")
	}
}

func TestDetectRoleBoundary_UnauthGets403NoTag(t *testing.T) {
	e := testEngine()
	ent := entWithIdentities(e, "http://example.com/admin", map[string]bool{
		"anonymous": false,
	})

	e.detectRoleBoundary(ent, map[string]int{"anonymous": 403})

	if ent.SeenSignal(knowledge.SigRoleBoundary) {
		t.Error("expected no SigRoleBoundary when only unauthenticated identity is denied")
	}
}

// -------------------------------------------------------
// detectAuthBoundary — synthetic identity exclusion (fix #5)
// -------------------------------------------------------

func TestDetectAuthBoundary_SyntheticCorruptedTokenSuccessDoesNotCount(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api")

	// corrupted-token sent credentials and happened to get accepted (200) —
	// that's a broken-token-validation finding (analyzeTokenValidation's
	// job), not evidence of an ordinary auth boundary. It must not count
	// toward hasAuthedSuccess.
	ent.AddIdentity(&knowledge.Identity{
		Name:      "corrupted-token",
		SentCreds: true,
		Kind:      knowledge.IdentityUser,
	})
	e.identities = append(e.identities, Identity{Name: "corrupted-token", Synthetic: true})

	ent.AddIdentity(&knowledge.Identity{
		Name:      "anonymous",
		SentCreds: false,
		Kind:      knowledge.IdentityNone,
	})
	e.identities = append(e.identities, Identity{Name: "anonymous", Synthetic: false})

	e.detectAuthBoundary(ent, map[string]int{
		"corrupted-token": 200,
		"anonymous":       401,
	})

	if ent.SeenSignal(knowledge.SigAuthBoundary) {
		t.Error("expected no SigAuthBoundary when the only 'authenticated success' came from a synthetic corrupted-token identity")
	}
}

func TestDetectAuthBoundary_GenuineSuccessStillCountsAlongsideSynthetic(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api")

	ent.AddIdentity(&knowledge.Identity{
		Name:      "session",
		SentCreds: true,
		Kind:      knowledge.IdentityUser,
	})
	e.identities = append(e.identities, Identity{Name: "session", Synthetic: false})

	ent.AddIdentity(&knowledge.Identity{
		Name:      "corrupted-token",
		SentCreds: true,
		Kind:      knowledge.IdentityUser,
	})
	e.identities = append(e.identities, Identity{Name: "corrupted-token", Synthetic: true})

	ent.AddIdentity(&knowledge.Identity{
		Name:      "anonymous",
		SentCreds: false,
		Kind:      knowledge.IdentityNone,
	})
	e.identities = append(e.identities, Identity{Name: "anonymous", Synthetic: false})

	e.detectAuthBoundary(ent, map[string]int{
		"session":         200,
		"corrupted-token": 200,
		"anonymous":       401,
	})

	if !ent.SeenSignal(knowledge.SigAuthBoundary) {
		t.Error("expected SigAuthBoundary from the genuine session success, even with a synthetic corrupted-token also present")
	}
}
