package httpintel

import (
	"cwrap/internal/recon/knowledge"
	"net/http"
	"testing"
)

func newEnt() *knowledge.Entity {
	return knowledge.NewEntity("http://example.com/test")
}

func resp(status int, headers map[string]string) *http.Response {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: status, Header: h}
}

// -------------------------------------------------------
// Status tracking
// -------------------------------------------------------

func TestLearn_StatusTracked(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, nil))
	Learn(ent, resp(200, nil))
	Learn(ent, resp(404, nil))

	if ent.Content.Statuses[200] != 2 {
		t.Errorf("expected 200 count=2, got %d", ent.Content.Statuses[200])
	}
	if ent.Content.Statuses[404] != 1 {
		t.Errorf("expected 404 count=1, got %d", ent.Content.Statuses[404])
	}
}

// -------------------------------------------------------
// Content-type detection
// -------------------------------------------------------

func TestLearn_JSONContentType(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{"Content-Type": "application/json"}))

	if !ent.Content.LooksLikeJSON {
		t.Error("expected LooksLikeJSON=true for application/json")
	}
}

func TestLearn_JSONWithCharset(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{"Content-Type": "application/json; charset=utf-8"}))

	if !ent.Content.LooksLikeJSON {
		t.Error("expected LooksLikeJSON=true for application/json with charset")
	}
}

func TestLearn_HTMLContentType(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{"Content-Type": "text/html; charset=utf-8"}))

	if !ent.Content.LooksLikeHTML {
		t.Error("expected LooksLikeHTML=true for text/html")
	}
}

func TestLearn_XMLContentType(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{"Content-Type": "application/xml"}))

	if !ent.Content.LooksLikeXML {
		t.Error("expected LooksLikeXML=true for application/xml")
	}
}

func TestLearn_NoContentTypeNoFlags(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, nil))

	if ent.Content.LooksLikeJSON || ent.Content.LooksLikeHTML || ent.Content.LooksLikeXML {
		t.Error("expected no content type flags when Content-Type header absent")
	}
}

// -------------------------------------------------------
// Auth signals
// -------------------------------------------------------

func TestLearn_WWWAuthenticateHeaderSetsAuthLikely(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(401, map[string]string{"Www-Authenticate": "Bearer realm=\"api\""}))

	if !ent.HTTP.AuthLikely {
		t.Error("expected AuthLikely=true for WWW-Authenticate header")
	}
}

func TestLearn_401SetsAuthLikely(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(401, nil))

	if !ent.HTTP.AuthLikely {
		t.Error("expected AuthLikely=true for 401 response")
	}
}

func TestLearn_403SetsAuthLikely(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(403, nil))

	if !ent.HTTP.AuthLikely {
		t.Error("expected AuthLikely=true for 403 response")
	}
}

func TestLearn_200DoesNotSetAuthLikely(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, nil))

	if ent.HTTP.AuthLikely {
		t.Error("expected AuthLikely=false for plain 200 response")
	}
}

// -------------------------------------------------------
// CSRF detection
// -------------------------------------------------------

func TestLearn_CSRFTokenHeaderDetected(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{"X-Csrf-Token": "abc123"}))

	if !ent.HTTP.CSRFPresent {
		t.Error("expected CSRFPresent=true for X-Csrf-Token header")
	}
}

func TestLearn_XSRFTokenHeaderDetected(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{"X-Xsrf-Token": "abc123"}))

	if !ent.HTTP.CSRFPresent {
		t.Error("expected CSRFPresent=true for X-Xsrf-Token header")
	}
}

func TestLearn_CSRFCookieDetected(t *testing.T) {
	ent := newEnt()
	h := http.Header{}
	h.Add("Set-Cookie", "csrf_token=abc123; Path=/; HttpOnly")
	Learn(ent, &http.Response{StatusCode: 200, Header: h})

	if !ent.HTTP.CSRFPresent {
		t.Error("expected CSRFPresent=true for csrf cookie")
	}
}

func TestLearn_NoCSRFSignals(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{"Content-Type": "application/json"}))

	if ent.HTTP.CSRFPresent {
		t.Error("expected CSRFPresent=false when no CSRF signals present")
	}
}
