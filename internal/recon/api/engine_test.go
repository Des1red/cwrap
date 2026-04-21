package api

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
			base:   "http://example.com",
			raw:    "javascript:void(0)",
			wantOK: false,
		},
		{
			name:   "tel scheme rejected",
			base:   "http://example.com",
			raw:    "tel:+1234567890",
			wantOK: false,
		},
		{
			name:   "empty rejected",
			base:   "http://example.com",
			raw:    "",
			wantOK: false,
		},
		{
			name:    "fragment stripped",
			base:    "http://example.com",
			raw:     "http://example.com/page#anchor",
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
// learnURLParams
// -------------------------------------------------------

func TestLearnURLParams_RegistersQueryParams(t *testing.T) {
	e := newEngine()
	e.learnURLParams("http://example.com/search?q=test&page=2&limit=10")

	ent := e.k.Entity("http://example.com/search?q=test&page=2&limit=10")

	for _, name := range []string{"q", "page", "limit"} {
		p := ent.Params[name]
		if p == nil {
			t.Errorf("expected param %q to be registered", name)
			continue
		}
		if !p.Sources[knowledge.ParamQuery] {
			t.Errorf("param %q expected source ParamQuery", name)
		}
	}
}

func TestLearnURLParams_NoParamsOnCleanURL(t *testing.T) {
	e := newEngine()
	e.learnURLParams("http://example.com/api/users")

	ent := e.k.Entity("http://example.com/api/users")
	if len(ent.Params) != 0 {
		t.Errorf("expected no params on URL without query string, got %v", ent.Params)
	}
}

func TestLearnURLParams_IDLikeParamClassified(t *testing.T) {
	e := newEngine()
	e.learnURLParams("http://example.com/api?user_id=5")

	ent := e.k.Entity("http://example.com/api?user_id=5")
	p := ent.Params["user_id"]
	if p == nil {
		t.Fatal("expected user_id param to be registered")
	}
	if !p.IDLike {
		t.Error("expected user_id to be classified as IDLike")
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
			t.Errorf("expected param %q to be registered", name)
			continue
		}
		if !p.Sources[knowledge.ParamJSON] {
			t.Errorf("param %q expected source ParamJSON", name)
		}
	}
}

func TestLearn_JSONSkippedOn4xx(t *testing.T) {
	e := newEngine()

	e.learn(
		"http://example.com/api/admin",
		testutil.MockResp(403, "application/json", testutil.ForbiddenJSON),
		testutil.ForbiddenJSON,
	)

	ent := e.k.Entity("http://example.com/api/admin")
	if len(ent.Params) > 0 {
		t.Errorf("expected no params on 403 response, got %v", ent.Params)
	}
}

func TestLearn_JSONSkippedOn5xx(t *testing.T) {
	e := newEngine()
	body := []byte(`{"error":"internal server error"}`)

	e.learn(
		"http://example.com/api/broken",
		testutil.MockResp(500, "application/json", body),
		body,
	)

	ent := e.k.Entity("http://example.com/api/broken")
	if len(ent.Params) > 0 {
		t.Errorf("expected no params on 500 response, got %v", ent.Params)
	}
}

func TestLearn_JSONArrayExtractsFirstElement(t *testing.T) {
	e := newEngine()

	e.learn(
		"http://example.com/api/posts",
		testutil.MockResp(200, "application/json", testutil.UsersJSON),
		testutil.UsersJSON,
	)

	ent := e.k.Entity("http://example.com/api/posts")

	for _, name := range []string{"id", "username"} {
		if ent.Params[name] == nil {
			t.Errorf("expected param %q from array first element, not found", name)
		}
	}
}

func TestLearn_ReflectionKeysNotRegistered(t *testing.T) {
	e := newEngine()

	e.learn(
		"http://example.com/api/thing",
		testutil.MockResp(200, "application/json", testutil.ErrorJSON),
		testutil.ErrorJSON,
	)

	ent := e.k.Entity("http://example.com/api/thing")

	// ErrorJSON contains "error", "message", "status" — all reflection keys
	// but also 2xx status, so the only reason they should be absent is the
	// reflectionKeys filter in jsonintel
	for _, skip := range []string{"error", "message", "status"} {
		if ent.Params[skip] != nil {
			t.Errorf("param %q is a reflection key and should not be registered", skip)
		}
	}
}

// -------------------------------------------------------
// learn — redirect following
// -------------------------------------------------------

func TestLearn_RedirectAddsEdge(t *testing.T) {
	e := newEngine()

	e.learn(
		"http://example.com/api/users",
		testutil.MockRespWithHeader(301, "text/html", "Location", "/v2/api/users", nil),
		nil,
	)

	found := false
	for _, edge := range e.k.Edges {
		if edge.From == "http://example.com/api/users" &&
			edge.To == "http://example.com/v2/api/users" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected redirect edge to /v2/api/users, not found")
	}
}
