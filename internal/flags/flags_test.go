package flags

import (
	"cwrap/internal/model"
	"testing"
)

// -------------------------------------------------------
// normalizeBasic — headers
// -------------------------------------------------------

func TestNormalizeBasic_ParsesHeaders(t *testing.T) {
	f := &model.Flags{}
	r := rawInput{
		headers: model.MultiValue{"Content-Type: application/json", "Authorization: Bearer token"},
	}
	normalizeBasic(f, r)

	if len(f.Headers) != 2 {
		t.Fatalf("expected 2 headers, got %d", len(f.Headers))
	}
	if f.Headers[0].Name != "Content-Type" || f.Headers[0].Value != "application/json" {
		t.Errorf("unexpected header[0]: %+v", f.Headers[0])
	}
	if f.Headers[1].Name != "Authorization" || f.Headers[1].Value != "Bearer token" {
		t.Errorf("unexpected header[1]: %+v", f.Headers[1])
	}
}

func TestNormalizeBasic_HeaderWithColonInValue(t *testing.T) {
	f := &model.Flags{}
	r := rawInput{
		headers: model.MultiValue{"X-Custom: value:with:colons"},
	}
	normalizeBasic(f, r)

	if len(f.Headers) != 1 {
		t.Fatalf("expected 1 header, got %d", len(f.Headers))
	}
	if f.Headers[0].Value != "value:with:colons" {
		t.Errorf("header value should preserve colons, got %q", f.Headers[0].Value)
	}
}

func TestNormalizeBasic_InvalidHeaderSkipped(t *testing.T) {
	f := &model.Flags{}
	r := rawInput{
		headers: model.MultiValue{"no-colon-at-all"},
	}
	normalizeBasic(f, r)

	if len(f.Headers) != 0 {
		t.Errorf("invalid header should be skipped, got %v", f.Headers)
	}
}

// -------------------------------------------------------
// normalizeBasic — cookies
// -------------------------------------------------------

func TestNormalizeBasic_ParsesCookies(t *testing.T) {
	f := &model.Flags{}
	r := rawInput{
		cookies: model.MultiValue{"session=abc123", "csrf=xyz"},
	}
	normalizeBasic(f, r)

	if len(f.Cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(f.Cookies))
	}
	if f.Cookies[0].Name != "session" || f.Cookies[0].Value != "abc123" {
		t.Errorf("unexpected cookie[0]: %+v", f.Cookies[0])
	}
}

func TestNormalizeBasic_InvalidCookieSkipped(t *testing.T) {
	f := &model.Flags{}
	r := rawInput{
		cookies: model.MultiValue{"no-equals-sign"},
	}
	normalizeBasic(f, r)

	if len(f.Cookies) != 0 {
		t.Errorf("invalid cookie should be skipped, got %v", f.Cookies)
	}
}

func TestNormalizeBasic_CookieWithEqualsInValue(t *testing.T) {
	f := &model.Flags{}
	r := rawInput{
		cookies: model.MultiValue{"token=abc=def"},
	}
	normalizeBasic(f, r)

	if len(f.Cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(f.Cookies))
	}
	if f.Cookies[0].Value != "abc=def" {
		t.Errorf("cookie value should preserve = signs, got %q", f.Cookies[0].Value)
	}
}

// -------------------------------------------------------
// normalizeQuery
// -------------------------------------------------------

func TestNormalizeQuery_ParsesParams(t *testing.T) {
	f := &model.Flags{}
	r := rawInput{
		query: model.MultiValue{"page=2", "limit=10"},
	}
	normalizeQuery(f, r)

	if len(f.Query) != 2 {
		t.Fatalf("expected 2 query params, got %d", len(f.Query))
	}
	if f.Query[0].Key != "page" || f.Query[0].Value != "2" {
		t.Errorf("unexpected query[0]: %+v", f.Query[0])
	}
	if f.Query[1].Key != "limit" || f.Query[1].Value != "10" {
		t.Errorf("unexpected query[1]: %+v", f.Query[1])
	}
}

func TestNormalizeQuery_InvalidParamSkipped(t *testing.T) {
	f := &model.Flags{}
	r := rawInput{
		query: model.MultiValue{"no-equals"},
	}
	normalizeQuery(f, r)

	if len(f.Query) != 0 {
		t.Errorf("invalid query param should be skipped, got %v", f.Query)
	}
}

func TestNormalizeQuery_EmptyInput(t *testing.T) {
	f := &model.Flags{}
	normalizeQuery(f, rawInput{})

	if len(f.Query) != 0 {
		t.Error("expected no query params for empty input")
	}
}

// -------------------------------------------------------
// normalizeForms
// -------------------------------------------------------

func TestNormalizeForms_ParsesTextField(t *testing.T) {
	f := &model.Flags{}
	r := rawInput{
		forms: model.MultiValue{"username=alice"},
	}
	normalizeForms(f, r)

	if len(f.Form) != 1 {
		t.Fatalf("expected 1 form field, got %d", len(f.Form))
	}
	field := f.Form[0]
	if field.Key != "username" || field.Value != "alice" {
		t.Errorf("unexpected field: %+v", field)
	}
	if field.IsFile {
		t.Error("text field should not be IsFile")
	}
}

func TestNormalizeForms_ParsesFileField(t *testing.T) {
	f := &model.Flags{}
	r := rawInput{
		forms: model.MultiValue{"file=@/tmp/test.jpg"},
	}
	normalizeForms(f, r)

	if len(f.Form) != 1 {
		t.Fatalf("expected 1 form field, got %d", len(f.Form))
	}
	field := f.Form[0]
	if !field.IsFile {
		t.Error("@ prefix should set IsFile=true")
	}
	if field.Value != "/tmp/test.jpg" {
		t.Errorf("expected Value=/tmp/test.jpg, got %q", field.Value)
	}
}

func TestNormalizeForms_ParsesFieldWithExtra(t *testing.T) {
	f := &model.Flags{}
	r := rawInput{
		forms: model.MultiValue{"file=@photo.jpg;type=image/jpeg"},
	}
	normalizeForms(f, r)

	field := f.Form[0]
	if field.Value != "photo.jpg" {
		t.Errorf("expected Value=photo.jpg, got %q", field.Value)
	}
	if field.Extra != ";type=image/jpeg" {
		t.Errorf("expected Extra=;type=image/jpeg, got %q", field.Extra)
	}
}

func TestNormalizeForms_InvalidFormSkipped(t *testing.T) {
	f := &model.Flags{}
	r := rawInput{
		forms: model.MultiValue{"no-equals-sign"},
	}
	normalizeForms(f, r)

	if len(f.Form) != 0 {
		t.Errorf("invalid form field should be skipped, got %v", f.Form)
	}
}

// -------------------------------------------------------
// applyProfiles
// -------------------------------------------------------

func TestApplyProfiles_JSONBody(t *testing.T) {
	f := &model.Flags{}
	r := rawInput{jsonBody: `{"key":"value"}`}
	applyProfiles(f, r)

	if !f.JSON {
		t.Error("expected JSON=true when jsonBody is set")
	}
	if f.Body != `{"key":"value"}` {
		t.Errorf("expected Body to be set, got %q", f.Body)
	}
	if f.ContentProfile != "json" {
		t.Errorf("expected ContentProfile=json, got %q", f.ContentProfile)
	}
}

func TestApplyProfiles_AsJSON(t *testing.T) {
	f := &model.Flags{}
	r := rawInput{asJSON: true}
	applyProfiles(f, r)

	if f.ContentProfile != "json" {
		t.Errorf("expected ContentProfile=json, got %q", f.ContentProfile)
	}
}

func TestApplyProfiles_AsForm(t *testing.T) {
	f := &model.Flags{}
	r := rawInput{asForm: true}
	applyProfiles(f, r)

	if f.ContentProfile != "form" {
		t.Errorf("expected ContentProfile=form, got %q", f.ContentProfile)
	}
}

func TestApplyProfiles_AsXML(t *testing.T) {
	f := &model.Flags{}
	r := rawInput{asXML: true}
	applyProfiles(f, r)

	if f.ContentProfile != "xml" {
		t.Errorf("expected ContentProfile=xml, got %q", f.ContentProfile)
	}
}

func TestApplyProfiles_NoInput(t *testing.T) {
	f := &model.Flags{}
	applyProfiles(f, rawInput{})

	if f.JSON || f.ContentProfile != "" {
		t.Error("expected no profile applied for empty input")
	}
}
