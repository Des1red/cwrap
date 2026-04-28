package intent

import (
	"cwrap/internal/model"
	"reflect"
	"testing"
)

func assertArgs(t *testing.T, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected args %v, got %v", want, got)
	}
}

// -------------------------------------------------------
// Parse / Resolve
// -------------------------------------------------------

func TestParse_Fetch(t *testing.T) {
	req := Parse([]string{"cwrap", "fetch", "http://example.com"})
	if req.Original != "fetch" || req.Method != "GET" || req.URL != "http://example.com" {
		t.Fatalf("unexpected request: %+v", req)
	}
}

func TestParse_Send(t *testing.T) {
	req := Parse([]string{"cwrap", "send", "http://example.com"})
	if req.Original != "send" || req.Method != "POST" || req.URL != "http://example.com" {
		t.Fatalf("unexpected request: %+v", req)
	}
}

func TestParse_Upload(t *testing.T) {
	req := Parse([]string{"cwrap", "upload", "http://example.com"})
	if req.Original != "upload" || req.Method != "POST" || req.URL != "http://example.com" {
		t.Fatalf("unexpected request: %+v", req)
	}
}

func TestParse_Recon(t *testing.T) {
	req := Parse([]string{"cwrap", "recon", "http://example.com"})
	if req.Original != "recon" || req.Method != "GET" || req.URL != "http://example.com" {
		t.Fatalf("unexpected request: %+v", req)
	}
}

func TestParse_Scan(t *testing.T) {
	req := Parse([]string{"cwrap", "scan", "http://example.com"})
	if req.Original != "scan" || req.Method != "GET" || req.URL != "http://example.com" {
		t.Fatalf("unexpected request: %+v", req)
	}
}

func TestParse_ExploitUsesFilePath(t *testing.T) {
	req := Parse([]string{"cwrap", "exploit", "report/test.report"})
	if req.Original != "exploit" || req.FilePath != "report/test.report" || req.URL != "" || req.Method != "" {
		t.Fatalf("unexpected request: %+v", req)
	}
}

func TestParse_RawHTTPMethods(t *testing.T) {
	cases := []struct {
		cmd    string
		method string
	}{
		{"get", "GET"},
		{"post", "POST"},
		{"put", "PUT"},
		{"delete", "DELETE"},
		{"download", "DOWNLOAD"},
	}

	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			req := Parse([]string{"cwrap", tc.cmd, "http://example.com"})
			if req.Original != tc.cmd || req.Method != tc.method || req.URL != "http://example.com" {
				t.Fatalf("unexpected request: %+v", req)
			}
		})
	}
}

func TestParse_TargetStartingWithFlagIsNotURL(t *testing.T) {
	req := Parse([]string{"cwrap", "fetch", "--follow"})
	if req.URL != "" || req.Method != "GET" || req.Original != "fetch" {
		t.Fatalf("unexpected request: %+v", req)
	}
}

func TestResolve_KnownHandlers(t *testing.T) {
	cases := []struct {
		original string
		wantType any
	}{
		{"fetch", FetchHandler{}},
		{"send", SendHandler{}},
		{"upload", UploadHandler{}},
		{"recon", &ReconHandler{}},
		{"scan", &ScanHandler{}},
		{"exploit", &ExploitHandler{}},
	}

	for _, tc := range cases {
		t.Run(tc.original, func(t *testing.T) {
			got := Resolve(model.Request{Original: tc.original})
			if reflect.TypeOf(got) != reflect.TypeOf(tc.wantType) {
				t.Fatalf("expected %T, got %T", tc.wantType, got)
			}
		})
	}
}

func TestResolve_UnknownReturnsNil(t *testing.T) {
	if got := Resolve(model.Request{Original: "unknown"}); got != nil {
		t.Fatalf("expected nil handler, got %T", got)
	}
}

// -------------------------------------------------------
// FetchHandler
// -------------------------------------------------------
func TestFetchTranslate_ProfileCookieBearerAndDefaultFollow(t *testing.T) {
	args := FetchHandler{}.Translate([]string{"firefox", "cookie:sid=abc", "bearer=tok"})
	assertArgs(t, args, []string{"-c", "sid=abc", "-b", "tok", "--as", "firefox"})
}

func TestFetchTranslate_QueryFromKeyValue(t *testing.T) {
	args := FetchHandler{}.Translate([]string{"page=2", "q=test"})
	assertArgs(t, args, []string{"-q", "page=2", "-q", "q=test"})
}

func TestFetchTranslate_FollowFalseIsNowQueryParam(t *testing.T) {
	args := FetchHandler{}.Translate([]string{"follow=false"})
	assertArgs(t, args, []string{"-q", "follow=false"})
}

func TestFetchTranslate_NoFollowWord(t *testing.T) {
	args := FetchHandler{}.Translate([]string{"nofollow"})
	assertArgs(t, args, []string{"--no-follow"})
}

func TestFetchTranslate_NoFollowHyphenWord(t *testing.T) {
	args := FetchHandler{}.Translate([]string{"no-follow"})
	assertArgs(t, args, []string{"--no-follow"})
}

func TestFetchTranslate_ProfileKeyValueIsNowQueryParamAndProxyShortcut(t *testing.T) {
	args := FetchHandler{}.Translate([]string{"profile=chrome", "proxy=http://127.0.0.1:8080"})
	assertArgs(t, args, []string{"-q", "profile=chrome", "--proxy", "http://127.0.0.1:8080"})
}

func TestFetchTranslate_SemanticBooleanWords(t *testing.T) {
	args := FetchHandler{}.Translate([]string{"csrf", "auto-cookie"})
	assertArgs(t, args, []string{"--csrf", "--auto-cookie"})
}

// -------------------------------------------------------
// SendHandler
// -------------------------------------------------------

func TestSendTranslate_JSONBody(t *testing.T) {
	args := SendHandler{}.Translate([]string{"json", "name=Alice", "age=42", "active=true"})
	assertArgs(t, args, []string{"-d", `{"active":true,"age":42,"name":"Alice"}`, "--as-json"})
}

func TestSendTranslate_FormBodyByDefault(t *testing.T) {
	args := SendHandler{}.Translate([]string{"name=Alice", "age=42"})
	assertArgs(t, args, []string{"-d", "name=Alice&age=42", "--as-form"})
}

func TestSendTranslate_ExplicitAsJsonFlagControlsInference(t *testing.T) {
	args := SendHandler{}.Translate([]string{"--as-json", "count=3"})
	assertArgs(t, args, []string{"-d", `{"count":3}`, "--as-json"})
}

func TestSendTranslate_ProfileCookieBearerAndSemanticFlags(t *testing.T) {
	args := SendHandler{}.Translate([]string{"api", "cookie:sid=abc", "auth=tok", "csrf", "name=Alice"})
	assertArgs(t, args, []string{"-c", "sid=abc", "-b", "tok", "--csrf", "-d", "name=Alice", "--as-form", "--as", "api"})
}

func TestSendTranslate_NestedJSONBody(t *testing.T) {
	args := SendHandler{}.Translate([]string{"json", "user.name=Alice", "user.age=24"})
	assertArgs(t, args, []string{"-d", `{"user":{"age":24,"name":"Alice"}}`, "--as-json"})
}

func TestSendApplyDefaults_POSTAndDebug(t *testing.T) {
	req := &model.Request{}
	f := &model.Flags{}
	SendHandler{}.ApplyDefaults(req, f)

	if req.Method != "POST" {
		t.Fatalf("expected POST, got %q", req.Method)
	}
	if !f.Debug {
		t.Fatal("expected Debug=true")
	}
}

// -------------------------------------------------------
// UploadHandler
// -------------------------------------------------------

func TestUploadTranslate_FileFieldProfileCookieBearer(t *testing.T) {
	args := UploadHandler{}.Translate([]string{"file=@shell.php", "desc=test", "firefox", "cookie:sid=abc", "bearer=tok"})
	assertArgs(t, args, []string{"-f", "file=@shell.php", "-f", "desc=test", "-c", "sid=abc", "-b", "tok", "--as", "firefox", "--debug"})
}

func TestUploadTranslate_SemanticFlags(t *testing.T) {
	args := UploadHandler{}.Translate([]string{"csrf", "auto-cookie", "file=@a.txt"})
	assertArgs(t, args, []string{"--csrf", "--auto-cookie", "-f", "file=@a.txt", "--debug"})
}

func TestUploadApplyDefaults_POSTDebugAndRequiresFile(t *testing.T) {
	req := &model.Request{}
	f := &model.Flags{Form: []model.FormField{{Key: "file", Value: "shell.php", IsFile: true}}}
	UploadHandler{}.ApplyDefaults(req, f)

	if req.Method != "POST" {
		t.Fatalf("expected POST, got %q", req.Method)
	}
	if !f.Debug {
		t.Fatal("expected Debug=true")
	}
}

// -------------------------------------------------------
// ReconHandler
// -------------------------------------------------------

func TestReconTranslate_CapturesModeProfileCookieBearer(t *testing.T) {
	h := &ReconHandler{}
	args := h.Translate([]string{"web", "firefox", "cookie:sid=abc", "bearer=tok"})
	assertArgs(t, args, nil)

	if h.reconMode != "web" || h.profile != "firefox" || h.bearer != "tok" {
		t.Fatalf("unexpected handler state: %+v", h)
	}
	if len(h.cookies) != 1 || h.cookies[0].Name != "sid" || h.cookies[0].Value != "abc" {
		t.Fatalf("unexpected cookies: %+v", h.cookies)
	}
}

func TestReconTranslate_APIModeDoesNotTreatAPIAsProfile(t *testing.T) {
	h := &ReconHandler{}
	args := h.Translate([]string{"api"})
	assertArgs(t, args, nil)

	if h.reconMode != "api" {
		t.Fatalf("expected reconMode api, got %q", h.reconMode)
	}
	if h.profile != "" {
		t.Fatalf("api recon mode should not also set profile, got %q", h.profile)
	}
}

func TestReconApplyDefaults(t *testing.T) {
	h := &ReconHandler{
		reconMode: "web",
		profile:   "firefox",
		cookies:   []model.Cookie{{Name: "sid", Value: "abc"}},
		bearer:    "tok",
	}
	req := &model.Request{}
	f := &model.Flags{}
	h.ApplyDefaults(req, f)

	if req.Method != "GET" || req.ReconMode != "web" {
		t.Fatalf("unexpected request: %+v", req)
	}
	if f.Profile != "firefox" || f.Bearer != "tok" {
		t.Fatalf("unexpected flags: %+v", f)
	}
	if len(f.Cookies) != 1 || f.Cookies[0].Name != "sid" || f.Cookies[0].Value != "abc" {
		t.Fatalf("unexpected cookies: %+v", f.Cookies)
	}
}

// -------------------------------------------------------
// ScanHandler
// -------------------------------------------------------

func TestScanHandlerTranslate_CapturesProfileCookieBearer(t *testing.T) {
	h := &ScanHandler{}
	args := h.Translate([]string{"firefox", "cookie:sid=abc", "token=tok", "--dir", "words.txt"})
	assertArgs(t, args, []string{"--dir", "words.txt"})

	if h.profile != "firefox" || h.bearer != "tok" {
		t.Fatalf("unexpected handler state: %+v", h)
	}
	if len(h.cookies) != 1 || h.cookies[0].Name != "sid" || h.cookies[0].Value != "abc" {
		t.Fatalf("unexpected cookies: %+v", h.cookies)
	}
}

func TestScanHandlerApplyDefaults(t *testing.T) {
	h := &ScanHandler{
		profile: "api",
		cookies: []model.Cookie{{Name: "sid", Value: "abc"}},
		bearer:  "tok",
	}
	req := &model.Request{}
	f := &model.Flags{DirWordlist: "dirs.txt", DomainWordlist: "subs.txt"}
	h.ApplyDefaults(req, f)

	if req.Method != "GET" || req.FilePath != "dirs.txt" || req.SubdomainFile != "subs.txt" {
		t.Fatalf("unexpected request: %+v", req)
	}
	if f.Profile != "api" || f.Bearer != "tok" {
		t.Fatalf("unexpected flags: %+v", f)
	}
	if len(f.Cookies) != 1 || f.Cookies[0].Name != "sid" || f.Cookies[0].Value != "abc" {
		t.Fatalf("unexpected cookies: %+v", f.Cookies)
	}
}

// -------------------------------------------------------
// ExploitHandler
// -------------------------------------------------------

func TestExploitTranslate_CapturesProfile(t *testing.T) {
	h := &ExploitHandler{}
	args := h.Translate([]string{"firefox", "extra"})
	assertArgs(t, args, []string{"extra"})

	if h.profile != "firefox" {
		t.Fatalf("expected profile firefox, got %q", h.profile)
	}
}

func TestExploitApplyDefaults(t *testing.T) {
	h := &ExploitHandler{profile: "curl"}
	req := &model.Request{Method: "GET"}
	f := &model.Flags{}
	h.ApplyDefaults(req, f)

	if req.Method != "" {
		t.Fatalf("expected empty method, got %q", req.Method)
	}
	if f.Profile != "curl" {
		t.Fatalf("expected profile curl, got %q", f.Profile)
	}
}
