package http

import (
	"cwrap/internal/recon/knowledge"
	"cwrap/testutil"
	"testing"
)

// -------------------------------------------------------
// helpers
// -------------------------------------------------------

func newEngine() *Engine {
	e := &Engine{}
	e.k = knowledge.New("http://example.com")
	return e
}

// -------------------------------------------------------
// normalizeLink
// -------------------------------------------------------

func TestNormalizeLink(t *testing.T) {
	e := newEngine()

	tests := []struct {
		name    string
		base    string
		raw     string
		wantURL string
		wantOK  bool
	}{
		{
			name:    "relative path",
			base:    "http://example.com/page",
			raw:     "/api/users",
			wantURL: "http://example.com/api/users",
			wantOK:  true,
		},
		{
			name:    "relative same-dir",
			base:    "http://example.com/page",
			raw:     "login",
			wantURL: "http://example.com/login",
			wantOK:  true,
		},
		{
			name:    "absolute same-host",
			base:    "http://example.com/page",
			raw:     "http://example.com/admin",
			wantURL: "http://example.com/admin",
			wantOK:  true,
		},
		{
			name:   "cross-domain rejected",
			base:   "http://example.com/page",
			raw:    "http://evil.com/steal",
			wantOK: false,
		},
		{
			name:   "fragment-only rejected",
			base:   "http://example.com/page",
			raw:    "#section",
			wantOK: false,
		},
		{
			name:   "javascript scheme rejected",
			base:   "http://example.com/page",
			raw:    "javascript:alert(1)",
			wantOK: false,
		},
		{
			name:   "mailto rejected",
			base:   "http://example.com/page",
			raw:    "mailto:user@example.com",
			wantOK: false,
		},
		{
			name:   "tel rejected",
			base:   "http://example.com",
			raw:    "tel:+1234567890",
			wantOK: false,
		},
		{
			name:   "empty rejected",
			base:   "http://example.com/page",
			raw:    "",
			wantOK: false,
		},
		{
			name:   "whitespace-only rejected",
			base:   "http://example.com/page",
			raw:    "   ",
			wantOK: false,
		},
		{
			name:    "fragment stripped from URL",
			base:    "http://example.com",
			raw:     "http://example.com/page#section",
			wantURL: "http://example.com/page",
			wantOK:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := e.normalizeLink(tt.base, tt.raw)
			if ok != tt.wantOK {
				t.Fatalf("normalizeLink(%q, %q) ok=%v want %v", tt.base, tt.raw, ok, tt.wantOK)
			}
			if ok && got != tt.wantURL {
				t.Errorf("normalizeLink(%q, %q) = %q want %q", tt.base, tt.raw, got, tt.wantURL)
			}
		})
	}
}

// -------------------------------------------------------
// looksLikeJSONBody
// -------------------------------------------------------

func TestLooksLikeJSONBody(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		want bool
	}{
		{"object", []byte(`{"id":1}`), true},
		{"array", []byte(`[{"id":1}]`), true},
		{"whitespace prefix object", []byte("  \n{\"id\":1}"), true},
		{"whitespace prefix array", []byte("\t[1,2,3]"), true},
		{"html", []byte(`<!doctype html><html>`), false},
		{"plain text", []byte("hello world"), false},
		{"empty", []byte{}, false},
		{"number only", []byte("42"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := looksLikeJSONBody(tt.body); got != tt.want {
				t.Errorf("looksLikeJSONBody(%q) = %v want %v", tt.body, got, tt.want)
			}
		})
	}
}

// -------------------------------------------------------
// looksLikeHTMLBody
// -------------------------------------------------------

func TestLooksLikeHTMLBody(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		want bool
	}{
		{"doctype", []byte(`<!doctype html><html><body></body></html>`), true},
		{"html tag", []byte(`<html><head></head><body></body></html>`), true},
		{"body tag present", []byte(`<div><body>content</body></div>`), true},
		{"uppercase doctype", []byte(`<!DOCTYPE HTML><HTML></HTML>`), true},
		{"json", []byte(`{"key":"value"}`), false},
		{"plain text", []byte("just some text"), false},
		{"empty", []byte{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := looksLikeHTMLBody(tt.body); got != tt.want {
				t.Errorf("looksLikeHTMLBody(%q) = %v want %v", tt.body, got, tt.want)
			}
		})
	}
}

// -------------------------------------------------------
// learn — JSON extraction
// -------------------------------------------------------

func TestLearn_JSONExtractsParamsOn2xx(t *testing.T) {
	e := newEngine()

	e.learn(
		"http://example.com/api/me",
		testutil.MockResp(200, "application/json", testutil.UserJSON),
		testutil.UserJSON,
	)

	ent := e.k.Entity("http://example.com/api/me")

	for _, name := range []string{"id", "username", "email", "role"} {
		p := ent.Params[name]
		if p == nil {
			t.Errorf("expected param %q to be registered, not found", name)
			continue
		}
		if !p.Sources[knowledge.ParamJSON] {
			t.Errorf("param %q expected source ParamJSON", name)
		}
	}
}

func TestLearn_JSONSkippedOnErrorResponse(t *testing.T) {
	e := newEngine()

	e.learn(
		"http://example.com/api/users/999",
		testutil.MockResp(404, "application/json", testutil.ErrorJSON),
		testutil.ErrorJSON,
	)

	ent := e.k.Entity("http://example.com/api/users/999")
	if len(ent.Params) > 0 {
		t.Errorf("expected no params on 404 response, got %v", ent.Params)
	}
}

func TestLearn_JSONSkippedOn401(t *testing.T) {
	e := newEngine()

	e.learn(
		"http://example.com/api/secret",
		testutil.MockResp(401, "application/json", testutil.ForbiddenJSON),
		testutil.ForbiddenJSON,
	)

	ent := e.k.Entity("http://example.com/api/secret")
	if len(ent.Params) > 0 {
		t.Errorf("expected no params on 401 response, got %v", ent.Params)
	}
}

// -------------------------------------------------------
// learn — redirect following
// -------------------------------------------------------

func TestLearn_RedirectAddsEdge(t *testing.T) {
	e := newEngine()

	e.learn(
		"http://example.com/",
		testutil.MockRespWithHeader(302, "text/html", "Location", "/login", nil),
		nil,
	)

	found := false
	for _, edge := range e.k.Edges {
		if edge.From == "http://example.com/" && edge.To == "http://example.com/login" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected redirect edge from / to /login, not found")
	}
}

func TestLearn_CrossDomainRedirectIgnored(t *testing.T) {
	e := newEngine()

	e.learn(
		"http://example.com/page",
		testutil.MockRespWithHeader(302, "text/html", "Location", "http://evil.com/phish", nil),
		nil,
	)

	for _, edge := range e.k.Edges {
		if edge.To == "http://evil.com/phish" {
			t.Error("cross-domain redirect should not create an edge")
		}
	}
}

// -------------------------------------------------------
// learn — HTML extraction
// -------------------------------------------------------

func TestLearn_HTMLExtractsLinks(t *testing.T) {
	e := newEngine()

	e.learn(
		"http://example.com/home",
		testutil.MockResp(200, "text/html", testutil.HomeHTML),
		testutil.HomeHTML,
	)

	expected := []string{
		"http://example.com/api/users",
		"http://example.com/api/posts",
		"http://example.com/admin",
	}
	for _, want := range expected {
		found := false
		for _, edge := range e.k.Edges {
			if edge.To == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected edge to %q not found", want)
		}
	}
}

func TestLearn_HTMLExtractsFormParams(t *testing.T) {
	e := newEngine()

	e.learn(
		"http://example.com/login",
		testutil.MockResp(200, "text/html", testutil.LoginHTML),
		testutil.LoginHTML,
	)

	ent := e.k.Entity("http://example.com/login")

	for _, name := range []string{"username", "password"} {
		p := ent.Params[name]
		if p == nil {
			t.Errorf("expected form param %q to be registered", name)
			continue
		}
		if !p.Sources[knowledge.ParamForm] {
			t.Errorf("param %q expected source ParamForm", name)
		}
	}
}
