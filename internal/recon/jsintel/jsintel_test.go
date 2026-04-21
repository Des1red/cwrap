package jsintel

import (
	"cwrap/internal/recon/knowledge"
	"testing"
)

const sourceURL = "http://example.com/app.js"

func newEnt() *knowledge.Entity {
	return knowledge.NewEntity(sourceURL)
}

func hasLeak(ent *knowledge.Entity, kind, key string) bool {
	for _, l := range ent.Content.JSLeaks {
		if l.Kind == kind && (key == "" || l.Key == key) {
			return true
		}
	}
	return false
}

func hasEndpoint(eps []JSEndpoint, method, path string) bool {
	for _, ep := range eps {
		if ep.Method == method && ep.Path == path {
			return true
		}
	}
	return false
}

// -------------------------------------------------------
// Endpoint discovery — fetch
// -------------------------------------------------------

func TestLearn_FetchEndpointDiscovered(t *testing.T) {
	ent := newEnt()
	body := []byte(`fetch("/api/users")`)

	eps := Learn(ent, sourceURL, body)

	if !hasEndpoint(eps, "GET", "/api/users") {
		t.Error("expected fetch endpoint GET /api/users")
	}
	if ent.Content.JSFindings["endpoint"] < 1 {
		t.Error("expected endpoint count > 0")
	}
}

func TestLearn_FetchSingleQuote(t *testing.T) {
	ent := newEnt()
	eps := Learn(ent, sourceURL, []byte(`fetch('/api/posts')`))
	if !hasEndpoint(eps, "GET", "/api/posts") {
		t.Error("expected fetch with single quotes to be discovered")
	}
}

// -------------------------------------------------------
// Endpoint discovery — axios
// -------------------------------------------------------

func TestLearn_AxiosGetDiscovered(t *testing.T) {
	ent := newEnt()
	eps := Learn(ent, sourceURL, []byte(`axios.get("/api/users")`))
	if !hasEndpoint(eps, "GET", "/api/users") {
		t.Error("expected axios GET endpoint")
	}
}

func TestLearn_AxiosPostDiscovered(t *testing.T) {
	ent := newEnt()
	eps := Learn(ent, sourceURL, []byte(`axios.post("/api/users", data)`))
	if !hasEndpoint(eps, "POST", "/api/users") {
		t.Error("expected axios POST endpoint")
	}
}

func TestLearn_AxiosDeleteDiscovered(t *testing.T) {
	ent := newEnt()
	eps := Learn(ent, sourceURL, []byte(`axios.delete("/api/users/1")`))
	if !hasEndpoint(eps, "DELETE", "/api/users/1") {
		t.Error("expected axios DELETE endpoint")
	}
}

// -------------------------------------------------------
// Endpoint discovery — XHR
// -------------------------------------------------------

func TestLearn_XHREndpointDiscovered(t *testing.T) {
	ent := newEnt()
	eps := Learn(ent, sourceURL, []byte(`xhr.open("POST", "/api/login")`))
	if !hasEndpoint(eps, "POST", "/api/login") {
		t.Error("expected XHR POST endpoint")
	}
}

func TestLearn_XHRGetDiscovered(t *testing.T) {
	ent := newEnt()
	eps := Learn(ent, sourceURL, []byte(`xhr.open("GET", "/api/status")`))
	if !hasEndpoint(eps, "GET", "/api/status") {
		t.Error("expected XHR GET endpoint")
	}
}

// -------------------------------------------------------
// Endpoint discovery — path literals
// -------------------------------------------------------

func TestLearn_PathLiteralDiscovered(t *testing.T) {
	ent := newEnt()
	eps := Learn(ent, sourceURL, []byte(`var url = "/api/admin/users"`))
	if !hasEndpoint(eps, "GET", "/api/admin/users") {
		t.Error("expected path literal /api/admin/users to be discovered")
	}
}

func TestLearn_PathLiteralFilteredForNonInteresting(t *testing.T) {
	ent := newEnt()
	// paths not matching the sensitive prefix filter should not appear
	eps := Learn(ent, sourceURL, []byte(`var url = "/static/logo.png"`))
	if hasEndpoint(eps, "GET", "/static/logo.png") {
		t.Error("non-interesting path /static/logo.png should not be discovered")
	}
}

// -------------------------------------------------------
// Deduplication
// -------------------------------------------------------

func TestLearn_DuplicateEndpointsDeduped(t *testing.T) {
	ent := newEnt()
	body := []byte(`
		fetch("/api/users")
		fetch("/api/users")
		axios.get("/api/users")
	`)
	eps := Learn(ent, sourceURL, body)

	count := 0
	for _, ep := range eps {
		if ep.Method == "GET" && ep.Path == "/api/users" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 deduplicated endpoint for GET /api/users, got %d", count)
	}
}

// -------------------------------------------------------
// Secret detection — JWT
// -------------------------------------------------------

func TestLearn_JWTDetected(t *testing.T) {
	ent := newEnt()
	body := []byte(`var token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`)

	Learn(ent, sourceURL, body)

	if !ent.SeenSignal(knowledge.SigSensitiveKeyword) {
		t.Error("expected SigSensitiveKeyword for JWT")
	}
	if ent.Content.JSFindings["jwt"] < 1 {
		t.Error("expected jwt finding count > 0")
	}
	if !hasLeak(ent, "jwt", "") {
		t.Error("expected jwt leak recorded")
	}
}

// -------------------------------------------------------
// Secret detection — AWS key
// -------------------------------------------------------

func TestLearn_AWSKeyDetected(t *testing.T) {
	ent := newEnt()
	body := []byte(`const accessKey = "AKIAIOSFODNN7EXAMPLE"`)

	Learn(ent, sourceURL, body)

	if !ent.SeenSignal(knowledge.SigSensitiveKeyword) {
		t.Error("expected SigSensitiveKeyword for AWS key")
	}
	if !hasLeak(ent, "aws_key", "access_key_id") {
		t.Error("expected aws_key leak recorded")
	}
}

// -------------------------------------------------------
// Secret detection — PEM key
// -------------------------------------------------------

func TestLearn_PEMKeyDetected(t *testing.T) {
	ent := newEnt()
	body := []byte(`var key = "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0..."`)

	Learn(ent, sourceURL, body)

	if !ent.SeenSignal(knowledge.SigSensitiveKeyword) {
		t.Error("expected SigSensitiveKeyword for PEM key")
	}
	if !hasLeak(ent, "pem", "private_key") {
		t.Error("expected pem leak recorded")
	}
}

// -------------------------------------------------------
// Secret detection — keyword assignments
// -------------------------------------------------------

func TestLearn_APIKeyAssignmentDetected(t *testing.T) {
	ent := newEnt()
	body := []byte(`var api_key = "sk-supersecretvalue123"`)

	Learn(ent, sourceURL, body)

	if !ent.SeenSignal(knowledge.SigSensitiveKeyword) {
		t.Error("expected SigSensitiveKeyword for api_key assignment")
	}
	if !hasLeak(ent, "keyword", "api_key") {
		t.Error("expected keyword leak with key=api_key")
	}
}

func TestLearn_PasswordAssignmentDetected(t *testing.T) {
	ent := newEnt()
	body := []byte(`const password = "hunter2secret"`)

	Learn(ent, sourceURL, body)

	if !hasLeak(ent, "keyword", "password") {
		t.Error("expected keyword leak with key=password")
	}
}

// -------------------------------------------------------
// Role / privilege surface detection
// -------------------------------------------------------

func TestLearn_RoleComparisonDetected(t *testing.T) {
	ent := newEnt()
	body := []byte(`if (user.role === "admin") { showPanel(); }`)

	Learn(ent, sourceURL, body)

	if ent.Content.JSFindings["role_check"] < 1 {
		t.Error("expected role_check finding")
	}
	if !hasLeak(ent, "role_check", "role") {
		t.Error("expected role_check leak")
	}
}

func TestLearn_IsAdminBoolDetected(t *testing.T) {
	ent := newEnt()
	body := []byte(`if (isAdmin === true) { renderAdminUI(); }`)

	Learn(ent, sourceURL, body)

	if ent.Content.JSFindings["priv_flag"] < 1 {
		t.Error("expected priv_flag finding for isAdmin")
	}
}

func TestLearn_PrivGateDetected(t *testing.T) {
	ent := newEnt()
	body := []byte(`if (claims.role && isAdmin) { next(); }`)

	Learn(ent, sourceURL, body)

	if ent.Content.JSFindings["priv_gate"] < 1 {
		t.Error("expected priv_gate finding")
	}
}

// -------------------------------------------------------
// Environment variable detection
// -------------------------------------------------------

func TestLearn_ProcessEnvDetected(t *testing.T) {
	ent := newEnt()
	body := []byte(`const url = process.env.API_URL`)

	Learn(ent, sourceURL, body)

	if ent.Content.JSFindings["env_ref"] < 1 {
		t.Error("expected env_ref finding for process.env")
	}
	if !hasLeak(ent, "env_ref", "process.env") {
		t.Error("expected env_ref leak")
	}
}

func TestLearn_ViteEnvDetected(t *testing.T) {
	ent := newEnt()
	body := []byte(`const key = import.meta.env.VITE_API_KEY`)

	Learn(ent, sourceURL, body)

	if ent.Content.JSFindings["env_ref"] < 1 {
		t.Error("expected env_ref finding for import.meta.env")
	}
}

func TestLearn_PublicEnvDetected(t *testing.T) {
	ent := newEnt()
	body := []byte(`const key = NEXT_PUBLIC_API_URL`)

	Learn(ent, sourceURL, body)

	if ent.Content.JSFindings["env_public"] < 1 {
		t.Error("expected env_public finding for NEXT_PUBLIC_*")
	}
}

// -------------------------------------------------------
// Internal infra detection
// -------------------------------------------------------

func TestLearn_InternalDomainDetected(t *testing.T) {
	ent := newEnt()
	body := []byte(`const api = "http://backend.internal/api"`)

	Learn(ent, sourceURL, body)

	if ent.Content.JSFindings["host_internal"] < 1 {
		t.Error("expected host_internal finding")
	}
	if !hasLeak(ent, "host_internal", "domain") {
		t.Error("expected host_internal leak")
	}
}

func TestLearn_RFC1918IPDetected(t *testing.T) {
	ent := newEnt()
	body := []byte(`const host = "192.168.1.100:8080"`)

	Learn(ent, sourceURL, body)

	if ent.Content.JSFindings["host_private_ip"] < 1 {
		t.Error("expected host_private_ip finding")
	}
}

func TestLearn_HardcodedURLDetected(t *testing.T) {
	ent := newEnt()
	body := []byte(`const endpoint = "https://api.example.com/v1/users"`)

	Learn(ent, sourceURL, body)

	if ent.Content.JSFindings["host_url"] < 1 {
		t.Error("expected host_url finding")
	}
}

// -------------------------------------------------------
// Feature flags
// -------------------------------------------------------

func TestLearn_FeatureTokenDetected(t *testing.T) {
	ent := newEnt()
	body := []byte(`if (FEATURE_DARK_MODE) { applyTheme(); }`)

	Learn(ent, sourceURL, body)

	if ent.Content.JSFindings["feature_token"] < 1 {
		t.Error("expected feature_token finding")
	}
}

func TestLearn_FeatureFlagBlockDetected(t *testing.T) {
	ent := newEnt()
	body := []byte(`const flags = { darkMode: true, betaFeature: false }`)

	Learn(ent, sourceURL, body)

	if ent.Content.JSFindings["feature_block"] < 1 {
		t.Error("expected feature_block finding")
	}
}

// -------------------------------------------------------
// Nil entity / empty body
// -------------------------------------------------------

func TestLearn_NilEntityReturnsNil(t *testing.T) {
	eps := Learn(nil, sourceURL, []byte(`fetch("/api/users")`))
	if eps != nil {
		t.Error("expected nil return for nil entity")
	}
}

func TestLearn_EmptyBodyNoFindings(t *testing.T) {
	ent := newEnt()
	eps := Learn(ent, sourceURL, []byte{})

	if len(eps) != 0 {
		t.Errorf("expected no endpoints from empty body, got %d", len(eps))
	}
	if len(ent.Content.JSLeaks) != 0 {
		t.Errorf("expected no leaks from empty body, got %d", len(ent.Content.JSLeaks))
	}
}

// -------------------------------------------------------
// Leak deduplication
// -------------------------------------------------------

func TestLearn_DuplicateLeaksDeduplicated(t *testing.T) {
	ent := newEnt()
	// same AWS key appears twice
	body := []byte(`
		const key1 = "AKIAIOSFODNN7EXAMPLE"
		const key2 = "AKIAIOSFODNN7EXAMPLE"
	`)

	Learn(ent, sourceURL, body)

	count := 0
	for _, l := range ent.Content.JSLeaks {
		if l.Kind == "aws_key" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 deduplicated aws_key leak, got %d", count)
	}
}
