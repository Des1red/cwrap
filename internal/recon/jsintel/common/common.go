package common

import (
	"cwrap/internal/recon/knowledge"
	"net/url"
	"regexp"
	"strings"
)

var (
	// --- secrets / keys ---
	ReJWT    = regexp.MustCompile(`\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	ReAWS    = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	RePEM    = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----`)
	ReAssign = regexp.MustCompile(`(?i)\b(api[_-]?key|client[_-]?secret|secret|token|bearer|authorization|private[_-]?key|password)\b\s*[:=]\s*["']([^"'\n\r]{6,})["']`)
	ReEmail  = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)

	// --- endpoint discovery ---
	// fetch("/path")  -> method unknown (assume GET)
	ReFetch = regexp.MustCompile(`(?i)\bfetch\(\s*["']([^"']+)["']`)

	// axios.get("/path") / axios.post("/path") ...
	// groups: (1)=method (2)=path
	ReAxios = regexp.MustCompile(`(?i)\baxios\.(get|post|put|delete|patch|options|head)\(\s*["']([^"']+)["']`)

	// xhr.open("POST", "/path")
	// groups: (1)=method (2)=path
	ReXHR = regexp.MustCompile(`(?i)\.open\(\s*["'](GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)["']\s*,\s*["']([^"']+)["']`)

	// string literals that *look* like interesting paths (tight filter)
	// group: (1)=path
	RePathLiteral = regexp.MustCompile(`["'](/(?:api|admin|internal|private|debug|graphql|v\d+|auth|login|logout|oauth|swagger)[^"']{0,200})["']`)

	// --- roles / privilege surfaces ---
	ReRoleCompare = regexp.MustCompile(`(?is)\b(role|user\.role|claims\.role)\s*(?:===|==|!=|!==)\s*["']([a-z0-9_-]{3,32})["']`)
	ReAdminBool   = regexp.MustCompile(`(?is)\b(isAdmin|admin|is_admin|superuser|isRoot|root)\b\s*(?:===|==|=)\s*(true|false)\b`)
	RePrivGate    = regexp.MustCompile(`(?is)\bif\s*\([^)]*(admin|isAdmin|superuser|root)[^)]*\)`)

	// --- feature flags ---
	ReFeatureToken  = regexp.MustCompile(`(?i)\b(FEATURE_[A-Z0-9_]{3,64}|FLAG_[A-Z0-9_]{3,64})\b`)
	ReFlagAssign    = regexp.MustCompile(`(?is)\b(flags?|featureFlags?|toggles?)\s*[:=]\s*\{[^}]{0,600}\}`)
	ReEnableDisable = regexp.MustCompile(`(?i)\b(enable|enabled|disable|disabled)\s*[_-]?\s*([a-z0-9_]{3,48})\b`)

	// --- env vars ---
	ReProcEnv       = regexp.MustCompile(`\bprocess\.env\.([A-Z0-9_]{2,64})\b`)
	ReImportMetaEnv = regexp.MustCompile(`\bimport\.meta\.env\.([A-Z0-9_]{2,64})\b`)
	RePublicEnv     = regexp.MustCompile(`\b(NEXT_PUBLIC_[A-Z0-9_]{2,64}|VITE_[A-Z0-9_]{2,64}|REACT_APP_[A-Z0-9_]{2,64})\b`)

	// --- hardcoded hosts / URLs ---
	ReURL            = regexp.MustCompile(`(?i)\b(https?|wss?)://[a-z0-9._-]+(?::\d{2,5})?(?:/[^\s"'<>]{0,200})?`)
	ReInternalDomain = regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9-]{3,})\.(local|lan|internal|intra|corp|home|test)\b`)
	ReRFC1918        = regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})(?::\d{2,5})?\b`)
)

type JSEndpoint struct {
	Path   string
	Method string
	Kind   string // "fetch", "axios", "xhr", "literal"
}

func AddJSEndpoint(ent *knowledge.Entity,
	out *[]JSEndpoint, seen map[string]bool, method, rawPath, kind string) bool {
	rawPath = strings.TrimSpace(rawPath)
	if rawPath == "" {
		return false
	}
	if strings.HasPrefix(rawPath, "data:") || strings.HasPrefix(rawPath, "blob:") {
		return false
	}

	method = strings.TrimSpace(strings.ToUpper(method))
	if method == "" {
		method = "GET"
	}

	key := method + "|" + rawPath
	if seen[key] {
		return false
	}
	seen[key] = true

	*out = append(*out, JSEndpoint{
		Path:   rawPath,
		Method: method,
		Kind:   kind,
	})
	if ent != nil && kind != "" {
		ent.Content.JSFindings["endpoint_"+kind]++
	}
	return true
}

func AppendJSEndpoint(
	out *[]JSEndpoint,
	seen map[string]bool,
	method,
	rawPath,
	kind string,
) bool {
	rawPath = strings.TrimSpace(rawPath)
	if rawPath == "" {
		return false
	}

	if strings.HasPrefix(rawPath, "data:") ||
		strings.HasPrefix(rawPath, "blob:") {
		return false
	}

	method = strings.TrimSpace(strings.ToUpper(method))
	if method == "" {
		method = "GET"
	}

	key := method + "|" + rawPath
	if seen[key] {
		return false
	}

	seen[key] = true

	*out = append(*out, JSEndpoint{
		Path:   rawPath,
		Method: method,
		Kind:   kind,
	})

	return true
}
func AppendLeak(ent *knowledge.Entity, kind, source, key, value string) {

	if ent.Content.SeenJSLeaks == nil {
		ent.Content.SeenJSLeaks = make(map[string]bool)
	}

	dedupe := kind + "|" + key + "|" + value

	if ent.Content.SeenJSLeaks[dedupe] {
		return
	}

	ent.Content.SeenJSLeaks[dedupe] = true

	ent.Content.JSLeaks = append(ent.Content.JSLeaks, knowledge.JSLeak{
		Kind:   kind,
		Source: source,
		Key:    key,
		Value:  value,
	})
}

func Redact(s string, max int) string {
	if max <= 0 {
		return ""
	}
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// JSPathSuffix extracts the /js/... suffix from a URL path.
// Returns "" if the URL doesn't contain a /js/ segment.
func JSPathSuffix(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	lower := strings.ToLower(u.Path)
	idx := strings.Index(lower, "/js/")
	if idx == -1 {
		return ""
	}
	return u.Path[idx:] // e.g. "/js/app.js"
}

// IsPhantomJSURL returns true if the URL is a path-prefix variant of an
// already-known JS file. This happens when a SPA returns its HTML shell for
// API routes — relative script imports resolve under the API prefix, producing
// phantom entities like /api/js/app.js when /js/app.js already exists.
func IsPhantomJSURL(k *knowledge.Knowledge, resolvedURL string) bool {
	suffix := JSPathSuffix(resolvedURL)
	if suffix == "" {
		return false
	}
	return k.HasJSSuffix(suffix)
}

// isNoiseURL returns true for URLs that are structurally valid but semantically
// useless for recon — XML namespaces, W3C schema URIs, CDN boilerplate, etc.
func IsNoiseURL(u string) bool {
	noise := []string{
		"www.w3.org",
		"schemas.xmlsoap.org",
		"schemas.microsoft.com",
		"purl.org",
		"dublincore.org",
		"ogp.me",
		"schema.org",
		"json-ld.org",
		"xmlns.com",
	}
	lower := strings.ToLower(u)
	for _, n := range noise {
		if strings.Contains(lower, n) {
			return true
		}
	}
	return false
}
