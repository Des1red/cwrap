package behavior

import (
	"cwrap/internal/recon/knowledge"
	"testing"
)

// -------------------------------------------------------
// analyzeTokenValidation
// -------------------------------------------------------

func TestAnalyzeTokenValidation_BrokenValidationFlagged(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/secure")
	e.authBoundaryConfirmed = true

	ent.AddProbeLog(knowledge.ProbeLogEntry{
		URL: ent.URL, Method: "GET", Identity: knowledge.Anonymous, Status: 401,
	})

	ent.AddIdentity(&knowledge.Identity{
		Name:      knowledge.CorruptedToken,
		SentCreds: true,
		Kind:      knowledge.IdentityUser,
	})
	ent.AddProbeLog(knowledge.ProbeLogEntry{
		URL: ent.URL, Method: "GET", Identity: knowledge.CorruptedToken, Status: 200,
	})

	e.analyzeTokenValidation(ent)

	if !ent.SeenSignal(knowledge.SigBrokenTokenValidation) {
		t.Error("expected SigBrokenTokenValidation when a corrupted bearer/cookie token was accepted after anon was denied")
	}
}

func TestAnalyzeTokenValidation_WeakOpaqueCookieFlagged(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/secure")
	e.authBoundaryConfirmed = true

	ent.AddProbeLog(knowledge.ProbeLogEntry{
		URL: ent.URL, Method: "GET", Identity: knowledge.Anonymous, Status: 403,
	})

	ent.AddIdentity(&knowledge.Identity{
		Name:      knowledge.CorruptedOpaqueCookieToken,
		SentCreds: true,
		Kind:      knowledge.IdentityUser,
	})
	ent.AddProbeLog(knowledge.ProbeLogEntry{
		URL: ent.URL, Method: "GET", Identity: knowledge.CorruptedOpaqueCookieToken, Status: 200,
	})

	e.analyzeTokenValidation(ent)

	if !ent.SeenSignal(knowledge.SigWeakOpaqueTokenValidation) {
		t.Error("expected SigWeakOpaqueTokenValidation when a corrupted opaque cookie was accepted after anon was denied")
	}
	if ent.SeenSignal(knowledge.SigBrokenTokenValidation) {
		t.Error("expected SigBrokenTokenValidation NOT set — opaque-cookie acceptance is a separate finding")
	}
}

func TestAnalyzeTokenValidation_NotConfirmedSkipped(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/secure")
	// authBoundaryConfirmed left false.

	ent.AddProbeLog(knowledge.ProbeLogEntry{
		URL: ent.URL, Method: "GET", Identity: knowledge.Anonymous, Status: 401,
	})
	ent.AddIdentity(&knowledge.Identity{Name: knowledge.CorruptedToken, SentCreds: true, Kind: knowledge.IdentityUser})
	ent.AddProbeLog(knowledge.ProbeLogEntry{
		URL: ent.URL, Method: "GET", Identity: knowledge.CorruptedToken, Status: 200,
	})

	e.analyzeTokenValidation(ent)

	if ent.SeenSignal(knowledge.SigBrokenTokenValidation) {
		t.Error("expected no signal when authBoundaryConfirmed is false")
	}
}

func TestAnalyzeTokenValidation_PublicAccessSkipped(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/secure")
	e.authBoundaryConfirmed = true
	ent.Tag(knowledge.SigPublicAccess)

	ent.AddProbeLog(knowledge.ProbeLogEntry{
		URL: ent.URL, Method: "GET", Identity: knowledge.Anonymous, Status: 401,
	})
	ent.AddIdentity(&knowledge.Identity{Name: knowledge.CorruptedToken, SentCreds: true, Kind: knowledge.IdentityUser})
	ent.AddProbeLog(knowledge.ProbeLogEntry{
		URL: ent.URL, Method: "GET", Identity: knowledge.CorruptedToken, Status: 200,
	})

	e.analyzeTokenValidation(ent)

	if ent.SeenSignal(knowledge.SigBrokenTokenValidation) {
		t.Error("expected no signal on a publicly-accessible entity")
	}
}

func TestAnalyzeTokenValidation_AnonNotDeniedSkipped(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/secure")
	e.authBoundaryConfirmed = true

	// anonymous succeeded, never denied.
	ent.AddProbeLog(knowledge.ProbeLogEntry{
		URL: ent.URL, Method: "GET", Identity: knowledge.Anonymous, Status: 200,
	})
	ent.AddIdentity(&knowledge.Identity{Name: knowledge.CorruptedToken, SentCreds: true, Kind: knowledge.IdentityUser})
	ent.AddProbeLog(knowledge.ProbeLogEntry{
		URL: ent.URL, Method: "GET", Identity: knowledge.CorruptedToken, Status: 200,
	})

	e.analyzeTokenValidation(ent)

	if ent.SeenSignal(knowledge.SigBrokenTokenValidation) {
		t.Error("expected no signal when anonymous was never denied — nothing to bypass")
	}
}

func TestAnalyzeTokenValidation_CorruptedIdentityNotAcceptedNoTag(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/secure")
	e.authBoundaryConfirmed = true

	ent.AddProbeLog(knowledge.ProbeLogEntry{
		URL: ent.URL, Method: "GET", Identity: knowledge.Anonymous, Status: 401,
	})

	// corrupted-token identity exists but was itself denied — no acceptance evidence.
	ent.AddIdentity(&knowledge.Identity{Name: knowledge.CorruptedToken, SentCreds: true, Kind: knowledge.IdentityUser})
	ent.AddProbeLog(knowledge.ProbeLogEntry{
		URL: ent.URL, Method: "GET", Identity: knowledge.CorruptedToken, Status: 401,
	})

	e.analyzeTokenValidation(ent)

	if ent.SeenSignal(knowledge.SigBrokenTokenValidation) {
		t.Error("expected no signal when the corrupted token was correctly rejected")
	}
}

// -------------------------------------------------------
// analyzeCredentiallessIssuance
// -------------------------------------------------------

func TestAnalyzeCredentiallessIssuance_AnonymousIssuedTokenFlagged(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/bootstrap")
	ent.HTTP.AuthLikely = true // stateful trigger

	ent.AddIdentity(&knowledge.Identity{
		Name:           "anonymous",
		SentCreds:      false,
		IssuedByServer: true,
		Rejected:       false,
		Kind:           knowledge.IdentityNone,
	})

	e.analyzeCredentiallessIssuance(ent)

	if !ent.SeenSignal(knowledge.SigCredentiallessTokenIssuance) {
		t.Error("expected SigCredentiallessTokenIssuance for an uncredentialed identity that got a server-issued token")
	}
}

func TestAnalyzeCredentiallessIssuance_NotStatefulSkipped(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/bootstrap")
	// No SigStateChanging, no SessionIssued, no AuthLikely — not stateful.

	ent.AddIdentity(&knowledge.Identity{
		Name:           "anonymous",
		SentCreds:      false,
		IssuedByServer: true,
		Rejected:       false,
		Kind:           knowledge.IdentityNone,
	})

	e.analyzeCredentiallessIssuance(ent)

	if ent.SeenSignal(knowledge.SigCredentiallessTokenIssuance) {
		t.Error("expected no signal when the entity isn't stateful, regardless of identity evidence")
	}
}

func TestAnalyzeCredentiallessIssuance_SentCredsIdentityDoesNotCount(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/bootstrap")
	ent.HTTP.AuthLikely = true

	ent.AddIdentity(&knowledge.Identity{
		Name:           "session",
		SentCreds:      true,
		IssuedByServer: true,
		Rejected:       false,
		Kind:           knowledge.IdentityUser,
	})

	e.analyzeCredentiallessIssuance(ent)

	if ent.SeenSignal(knowledge.SigCredentiallessTokenIssuance) {
		t.Error("expected no signal when the token-issued identity actually sent credentials")
	}
}

func TestAnalyzeCredentiallessIssuance_RejectedIdentityDoesNotCount(t *testing.T) {
	e := testEngine()
	ent := e.k.Entity("http://example.com/api/bootstrap")
	ent.HTTP.AuthLikely = true

	ent.AddIdentity(&knowledge.Identity{
		Name:           "anonymous",
		SentCreds:      false,
		IssuedByServer: true,
		Rejected:       true,
		Kind:           knowledge.IdentityInvalid,
	})

	e.analyzeCredentiallessIssuance(ent)

	if ent.SeenSignal(knowledge.SigCredentiallessTokenIssuance) {
		t.Error("expected no signal when the identity was rejected")
	}
}
