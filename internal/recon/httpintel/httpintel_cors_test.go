package httpintel

import (
	"net/http"
	"testing"
)

func TestLearnCORS_WildcardWithCredentials(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{
		"Access-Control-Allow-Origin":      "*",
		"Access-Control-Allow-Credentials": "true",
	}))

	if !ent.HTTP.CORSPermissive {
		t.Error("expected CORSPermissive=true for wildcard origin + credentials")
	}
	if ent.HTTP.CORSOrigin != "*" {
		t.Errorf("expected CORSOrigin=*, got %q", ent.HTTP.CORSOrigin)
	}
}

func TestLearnCORS_WildcardWithoutCredentials(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{
		"Access-Control-Allow-Origin": "*",
	}))

	if ent.HTTP.CORSPermissive {
		t.Error("expected CORSPermissive=false for wildcard origin without credentials — not dangerous on its own")
	}
}

func TestLearnCORS_SpecificOriginWithoutCredentials(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{
		"Access-Control-Allow-Origin": "https://trusted.example.com",
	}))

	if ent.HTTP.CORSPermissive {
		t.Error("expected CORSPermissive=false for a specific, non-reflected origin")
	}
}

func TestLearnCORS_ReflectedOriginWithCredentials(t *testing.T) {
	ent := newEnt()

	req, _ := http.NewRequest("GET", "http://example.com/api", nil)
	req.Header.Set("Origin", "https://evil.example.com")

	h := http.Header{}
	h.Set("Access-Control-Allow-Origin", "https://evil.example.com")
	h.Set("Access-Control-Allow-Credentials", "true")

	r := &http.Response{StatusCode: 200, Header: h, Request: req}
	Learn(ent, r)

	if !ent.HTTP.CORSPermissive {
		t.Error("expected CORSPermissive=true when Allow-Origin reflects request Origin with credentials")
	}
	if ent.HTTP.CORSOrigin != "https://evil.example.com" {
		t.Errorf("expected CORSOrigin to record the reflected origin, got %q", ent.HTTP.CORSOrigin)
	}
}

func TestLearnCORS_NoOriginHeaderNoFlag(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, nil))

	if ent.HTTP.CORSPermissive {
		t.Error("expected CORSPermissive=false when no Access-Control-Allow-Origin header present")
	}
}

func TestLearnCORS_NilRequestDoesNotPanic(t *testing.T) {
	ent := newEnt()
	// resp() helper builds a bare *http.Response with Request == nil —
	// this must not panic even though the reflection check reads resp.Request.
	Learn(ent, resp(200, map[string]string{
		"Access-Control-Allow-Origin":      "https://trusted.example.com",
		"Access-Control-Allow-Credentials": "true",
	}))

	if ent.HTTP.CORSPermissive {
		t.Error("expected CORSPermissive=false: origin is specific and non-reflected, and Request is nil so reflection can't be checked")
	}
}
