package curl

import (
	"cwrap/internal/model"
	"strings"
	"testing"
)

// -------------------------------------------------------
// shellEscape
// -------------------------------------------------------

func TestShellEscape_SafeStringUnchanged(t *testing.T) {
	for _, s := range []string{"curl", "http://example.com", "-H", "application/json"} {
		got := shellEscape(s)
		if got != s {
			t.Errorf("shellEscape(%q) = %q want unchanged", s, got)
		}
	}
}

func TestShellEscape_EmptyStringQuoted(t *testing.T) {
	got := shellEscape("")
	if got != "''" {
		t.Errorf("shellEscape(\"\") = %q want \"''\"", got)
	}
}

func TestShellEscape_SpaceWrappedInSingleQuotes(t *testing.T) {
	got := shellEscape("hello world")
	if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
		t.Errorf("shellEscape(%q) = %q expected single-quoted", "hello world", got)
	}
}

func TestShellEscape_SingleQuoteEscaped(t *testing.T) {
	// input: it's
	// expected POSIX: 'it'\''s'
	got := shellEscape("it's")
	if !strings.Contains(got, `'\''`) {
		t.Errorf("shellEscape(%q) = %q expected POSIX single-quote escape", "it's", got)
	}
}

func TestShellEscape_DollarSignQuoted(t *testing.T) {
	got := shellEscape("$HOME")
	if !strings.HasPrefix(got, "'") {
		t.Errorf("shellEscape(%q) = %q expected quoted ($ is unsafe)", "$HOME", got)
	}
}

func TestShellEscape_BacktickQuoted(t *testing.T) {
	got := shellEscape("`cmd`")
	if !strings.HasPrefix(got, "'") {
		t.Errorf("shellEscape(%q) = %q expected quoted (backtick is unsafe)", "`cmd`", got)
	}
}

// -------------------------------------------------------
// buildString
// -------------------------------------------------------

func TestBuildString_StartsWithCurl(t *testing.T) {
	got := buildString([]string{"-X", "POST", "http://example.com"})
	if !strings.HasPrefix(got, "curl ") {
		t.Errorf("buildString should start with 'curl ', got %q", got)
	}
}

func TestBuildString_ArgsPresent(t *testing.T) {
	got := buildString([]string{"-H", "Content-Type: application/json", "http://example.com"})
	if !strings.Contains(got, "Content-Type") {
		t.Errorf("buildString should contain header, got %q", got)
	}
}

// -------------------------------------------------------
// applyQuery
// -------------------------------------------------------

func TestApplyQuery_AddsParams(t *testing.T) {
	got := applyQuery("http://example.com/api", []model.QueryParam{
		{Key: "page", Value: "2"},
		{Key: "limit", Value: "10"},
	})
	if !strings.Contains(got, "page=2") {
		t.Errorf("applyQuery missing page=2, got %q", got)
	}
	if !strings.Contains(got, "limit=10") {
		t.Errorf("applyQuery missing limit=10, got %q", got)
	}
}

func TestApplyQuery_NoParamsUnchanged(t *testing.T) {
	raw := "http://example.com/api"
	got := applyQuery(raw, nil)
	if got != raw {
		t.Errorf("applyQuery with no params changed URL: %q", got)
	}
}

func TestApplyQuery_ExistingParamsPreserved(t *testing.T) {
	got := applyQuery("http://example.com/api?existing=1", []model.QueryParam{
		{Key: "new", Value: "2"},
	})
	if !strings.Contains(got, "existing=1") {
		t.Errorf("applyQuery lost existing param, got %q", got)
	}
	if !strings.Contains(got, "new=2") {
		t.Errorf("applyQuery missing new param, got %q", got)
	}
}

func TestApplyQuery_InvalidURLReturnedUnchanged(t *testing.T) {
	raw := "://invalid"
	got := applyQuery(raw, []model.QueryParam{{Key: "x", Value: "1"}})
	if got != raw {
		t.Errorf("applyQuery with invalid URL should return unchanged, got %q", got)
	}
}

// -------------------------------------------------------
// needsExplicitMethod
// -------------------------------------------------------

func TestNeedsExplicitMethod(t *testing.T) {
	tests := []struct {
		method  string
		hasBody bool
		want    bool
	}{
		{"GET", false, false},    // GET never needs -X
		{"GET", true, false},     // GET with body still no -X
		{"POST", true, false},    // POST with body — curl handles it
		{"POST", false, true},    // POST without body needs -X POST
		{"PUT", false, true},     // PUT always needs -X
		{"PUT", true, true},      // PUT with body still needs -X
		{"DELETE", false, true},  // DELETE always needs -X
		{"PATCH", false, true},   // PATCH always needs -X
		{"OPTIONS", false, true}, // non-standard needs -X
	}

	for _, tt := range tests {
		got := needsExplicitMethod(tt.method, tt.hasBody)
		if got != tt.want {
			t.Errorf("needsExplicitMethod(%q, %v) = %v want %v", tt.method, tt.hasBody, got, tt.want)
		}
	}
}

// -------------------------------------------------------
// buildMethod
// -------------------------------------------------------

func TestBuildMethod_GetNoArgs(t *testing.T) {
	req := model.Request{Method: "GET"}
	args := buildMethod(req)
	for _, a := range args {
		if a == "-X" {
			t.Error("GET should not produce -X flag")
		}
	}
}

func TestBuildMethod_HeadProducesI(t *testing.T) {
	req := model.Request{Method: "GET", Flags: model.Flags{Head: true}}
	args := buildMethod(req)
	found := false
	for _, a := range args {
		if a == "-I" {
			found = true
		}
	}
	if !found {
		t.Error("HEAD request should produce -I flag")
	}
}

func TestBuildMethod_PutProducesX(t *testing.T) {
	req := model.Request{Method: "PUT"}
	args := buildMethod(req)
	found := false
	for i, a := range args {
		if a == "-X" && i+1 < len(args) && args[i+1] == "PUT" {
			found = true
		}
	}
	if !found {
		t.Error("PUT request should produce -X PUT")
	}
}

// -------------------------------------------------------
// buildBody
// -------------------------------------------------------

func TestBuildBody_AddsDataFlag(t *testing.T) {
	req := model.Request{Flags: model.Flags{Body: `{"key":"value"}`}}
	args := buildBody([]string{}, req)
	found := false
	for i, a := range args {
		if a == "-d" && i+1 < len(args) {
			found = true
		}
	}
	if !found {
		t.Error("body should produce -d flag")
	}
}

func TestBuildBody_HeadSkipsBody(t *testing.T) {
	req := model.Request{Flags: model.Flags{Body: "data", Head: true}}
	args := buildBody([]string{}, req)
	for _, a := range args {
		if a == "-d" {
			t.Error("HEAD request should not include body")
		}
	}
}

func TestBuildBody_EmptyBodyNoArgs(t *testing.T) {
	req := model.Request{}
	args := buildBody([]string{}, req)
	if len(args) != 0 {
		t.Errorf("empty body should produce no args, got %v", args)
	}
}

// -------------------------------------------------------
// appendHeaderArgs
// -------------------------------------------------------

func TestAppendHeaderArgs_AddsHFlag(t *testing.T) {
	headers := []model.Header{
		{Name: "Content-Type", Value: "application/json"},
		{Name: "Authorization", Value: "Bearer token"},
	}
	args := appendHeaderArgs([]string{}, headers)

	if len(args) != 4 {
		t.Errorf("expected 4 args (2x -H + value), got %d", len(args))
	}
	for i := 0; i < len(args)-1; i += 2 {
		if args[i] != "-H" {
			t.Errorf("expected -H at position %d, got %q", i, args[i])
		}
	}
}

func TestAppendHeaderArgs_EmptyHeaders(t *testing.T) {
	args := appendHeaderArgs([]string{"existing"}, nil)
	if len(args) != 1 {
		t.Errorf("empty headers should not add args, got %v", args)
	}
}

// -------------------------------------------------------
// csrfHeaderName
// -------------------------------------------------------

func TestCSRFHeaderName(t *testing.T) {
	tests := []struct {
		cookie string
		want   string
	}{
		{"csrftoken", "X-CSRFToken"},
		{"xsrf-token", "X-XSRF-TOKEN"},
		{"_csrf", "X-CSRF-Token"},
		{"csrf_token", "X-CSRF-Token"}, // default
		{"unknown", "X-CSRF-Token"},    // default
	}

	for _, tt := range tests {
		got := csrfHeaderName(tt.cookie)
		if got != tt.want {
			t.Errorf("csrfHeaderName(%q) = %q want %q", tt.cookie, got, tt.want)
		}
	}
}

// -------------------------------------------------------
// requestHost
// -------------------------------------------------------

func TestRequestHost(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"http://example.com/api/users", "example.com"},
		{"https://api.example.com:8080/v1", "api.example.com"},
		{"http://localhost:9000/", "localhost"},
		{"://invalid", ""},
	}

	for _, tt := range tests {
		got := requestHost(tt.url)
		if got != tt.want {
			t.Errorf("requestHost(%q) = %q want %q", tt.url, got, tt.want)
		}
	}
}

// -------------------------------------------------------
// detectMime
// -------------------------------------------------------

func TestDetectMime(t *testing.T) {
	tests := []struct {
		path    string
		wantNot string // just check it's non-empty for known types
		wantOK  bool
	}{
		{"photo.jpg", "", true},
		{"doc.pdf", "", true},
		{"image.png", "", true},
		{"noextension", "", false},
		{"", "", false},
	}

	for _, tt := range tests {
		got := detectMime(tt.path)
		if tt.wantOK && got == "" {
			t.Errorf("detectMime(%q) expected non-empty MIME type", tt.path)
		}
		if !tt.wantOK && got != "" {
			t.Errorf("detectMime(%q) = %q expected empty", tt.path, got)
		}
	}
}
