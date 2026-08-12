package httpintel

import (
	"cwrap/internal/recon/knowledge"
	"testing"
)

func TestLearnSecurityHeaders_MissingOnHTML(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{"Content-Type": "text/html"}))

	if len(ent.HTTP.MissingSecurityHeaders) != 4 {
		t.Fatalf("expected all 4 hardening headers reported missing, got %d: %v",
			len(ent.HTTP.MissingSecurityHeaders), ent.HTTP.MissingSecurityHeaders)
	}
}

func TestLearnSecurityHeaders_AllPresentOnHTML(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{
		"Content-Type":              "text/html",
		"Content-Security-Policy":   "default-src 'self'",
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"Strict-Transport-Security": "max-age=31536000",
	}))

	if len(ent.HTTP.MissingSecurityHeaders) != 0 {
		t.Errorf("expected no missing headers, got %v", ent.HTTP.MissingSecurityHeaders)
	}
}

func TestLearnSecurityHeaders_PartiallyMissingOnHTML(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{
		"Content-Type":            "text/html",
		"Content-Security-Policy": "default-src 'self'",
	}))

	if len(ent.HTTP.MissingSecurityHeaders) != 3 {
		t.Fatalf("expected 3 missing headers, got %d: %v",
			len(ent.HTTP.MissingSecurityHeaders), ent.HTTP.MissingSecurityHeaders)
	}
}

func TestLearnSecurityHeaders_SkippedOnJSON(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{"Content-Type": "application/json"}))

	if ent.HTTP.MissingSecurityHeaders != nil {
		t.Errorf("expected no missing-headers evaluation on non-HTML content, got %v", ent.HTTP.MissingSecurityHeaders)
	}
}

func TestLearnSecurityHeaders_SkippedWhenNoContentType(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, nil))

	if ent.HTTP.MissingSecurityHeaders != nil {
		t.Errorf("expected no missing-headers evaluation without Content-Type, got %v", ent.HTTP.MissingSecurityHeaders)
	}
}

func TestLearnSecurityHeaders_CSPFrameAncestorsSuppressesXFO(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{
		"Content-Type":              "text/html",
		"Content-Security-Policy":   "default-src 'self'; frame-ancestors 'none'",
		"X-Content-Type-Options":    "nosniff",
		"Strict-Transport-Security": "max-age=31536000",
	}))

	for _, h := range ent.HTTP.MissingSecurityHeaders {
		if h == "X-Frame-Options" {
			t.Errorf("expected X-Frame-Options not flagged missing when CSP has frame-ancestors, got missing=%v", ent.HTTP.MissingSecurityHeaders)
		}
	}
	if len(ent.HTTP.MissingSecurityHeaders) != 0 {
		t.Errorf("expected no missing headers (CSP itself present, frame-ancestors covers XFO), got %v", ent.HTTP.MissingSecurityHeaders)
	}
}

func TestLearnSecurityHeaders_CSPWithoutFrameAncestorsStillFlagsXFO(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{
		"Content-Type":            "text/html",
		"Content-Security-Policy": "default-src 'self'; script-src 'self'",
	}))

	found := false
	for _, h := range ent.HTTP.MissingSecurityHeaders {
		if h == "X-Frame-Options" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected X-Frame-Options still flagged missing when CSP present but lacks frame-ancestors, got %v", ent.HTTP.MissingSecurityHeaders)
	}
}

func TestLearnSecurityHeaders_NoCSPStillFlagsXFO(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{"Content-Type": "text/html"}))

	found := false
	for _, h := range ent.HTTP.MissingSecurityHeaders {
		if h == "X-Frame-Options" {
			found = true
		}
	}
	if !found {
		t.Error("expected X-Frame-Options flagged missing when no CSP present at all")
	}
}

func TestLearnSecurityHeaders_WildcardFrameAncestorsFlagged(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{
		"Content-Type":              "text/html",
		"Content-Security-Policy":   "default-src 'self'; frame-ancestors *",
		"X-Content-Type-Options":    "nosniff",
		"Strict-Transport-Security": "max-age=31536000",
	}))

	if !ent.SeenSignal(knowledge.SigPermissiveFrameAncestors) {
		t.Error("expected SigPermissiveFrameAncestors for frame-ancestors *")
	}
	if ent.HTTP.FrameAncestors != "*" {
		t.Errorf("expected FrameAncestors=*, got %q", ent.HTTP.FrameAncestors)
	}
}

func TestLearnSecurityHeaders_StrictFrameAncestorsNotFlagged(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{
		"Content-Type":              "text/html",
		"Content-Security-Policy":   "default-src 'self'; frame-ancestors 'none'",
		"X-Content-Type-Options":    "nosniff",
		"Strict-Transport-Security": "max-age=31536000",
	}))

	if ent.SeenSignal(knowledge.SigPermissiveFrameAncestors) {
		t.Error("expected no SigPermissiveFrameAncestors for frame-ancestors 'none'")
	}
	if ent.HTTP.FrameAncestors != "'none'" {
		t.Errorf("expected FrameAncestors='none', got %q", ent.HTTP.FrameAncestors)
	}
}

func TestLearnSecurityHeaders_SelfFrameAncestorsNotFlagged(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{
		"Content-Type":              "text/html",
		"Content-Security-Policy":   "frame-ancestors 'self'",
		"X-Content-Type-Options":    "nosniff",
		"Strict-Transport-Security": "max-age=31536000",
	}))

	if ent.SeenSignal(knowledge.SigPermissiveFrameAncestors) {
		t.Error("expected no SigPermissiveFrameAncestors for frame-ancestors 'self'")
	}
}

func TestLearnSecurityHeaders_ScopedWildcardSubdomainNotFlagged(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{
		"Content-Type":            "text/html",
		"Content-Security-Policy": "frame-ancestors https://*.example.com",
	}))

	// Documents current, deliberate scope: scheme/subdomain wildcards are
	// narrower than a bare "*" and are not flagged by this check.
	if ent.SeenSignal(knowledge.SigPermissiveFrameAncestors) {
		t.Error("expected scoped wildcard (https://*.example.com) not flagged permissive")
	}
}

func TestLearnSecurityHeaders_NoFrameAncestorsNoPermissiveSignal(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{"Content-Type": "text/html"}))

	if ent.SeenSignal(knowledge.SigPermissiveFrameAncestors) {
		t.Error("expected no SigPermissiveFrameAncestors when frame-ancestors absent entirely")
	}
	if ent.HTTP.FrameAncestors != "" {
		t.Errorf("expected empty FrameAncestors, got %q", ent.HTTP.FrameAncestors)
	}
}

func TestCSPFrameAncestorsValue_ExtractsMultipleSources(t *testing.T) {
	value, ok := cspFrameAncestorsValue("default-src 'self'; frame-ancestors 'self' https://trusted.example")
	if !ok {
		t.Fatal("expected frame-ancestors to be found")
	}
	if value != "'self' https://trusted.example" {
		t.Errorf("expected full source list preserved, got %q", value)
	}
}

func TestFrameAncestorsIsPermissive_BareWildcard(t *testing.T) {
	if !frameAncestorsIsPermissive("*") {
		t.Error("expected bare * to be permissive")
	}
}

func TestFrameAncestorsIsPermissive_WildcardAmongOtherSources(t *testing.T) {
	if !frameAncestorsIsPermissive("'self' *") {
		t.Error("expected * anywhere in the source list to be permissive")
	}
}

func TestFrameAncestorsIsPermissive_NonWildcardSources(t *testing.T) {
	if frameAncestorsIsPermissive("'self' https://trusted.example") {
		t.Error("expected specific sources not to be flagged permissive")
	}
}
