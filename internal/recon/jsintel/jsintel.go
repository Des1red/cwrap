package jsintel

import (
	"cwrap/internal/recon/knowledge"
	"net/url"
	"regexp"
	"strings"
)

var (
	// --- secrets / keys ---
	reJWT    = regexp.MustCompile(`\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	reAWS    = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	rePEM    = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----`)
	reAssign = regexp.MustCompile(`(?i)\b(api[_-]?key|client[_-]?secret|secret|token|bearer|authorization|private[_-]?key|password)\b\s*[:=]\s*["']([^"'\n\r]{6,})["']`)

	// --- endpoint discovery ---
	// fetch("/path")  -> method unknown (assume GET)
	reFetch = regexp.MustCompile(`(?i)\bfetch\(\s*["']([^"']+)["']`)

	// axios.get("/path") / axios.post("/path") ...
	// groups: (1)=method (2)=path
	reAxios = regexp.MustCompile(`(?i)\baxios\.(get|post|put|delete|patch|options|head)\(\s*["']([^"']+)["']`)

	// xhr.open("POST", "/path")
	// groups: (1)=method (2)=path
	reXHR = regexp.MustCompile(`(?i)\.open\(\s*["'](GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)["']\s*,\s*["']([^"']+)["']`)

	// string literals that *look* like interesting paths (tight filter)
	// group: (1)=path
	rePathLiteral = regexp.MustCompile(`["'](/(?:api|admin|internal|private|debug|graphql|v\d+|auth|login|logout|oauth|swagger)[^"']{0,200})["']`)

	// --- roles / privilege surfaces ---
	reRoleCompare = regexp.MustCompile(`(?is)\b(role|user\.role|claims\.role)\s*(?:===|==|!=|!==)\s*["']([a-z0-9_-]{3,32})["']`)
	reAdminBool   = regexp.MustCompile(`(?is)\b(isAdmin|admin|is_admin|superuser|isRoot|root)\b\s*(?:===|==|=)\s*(true|false)\b`)
	rePrivGate    = regexp.MustCompile(`(?is)\bif\s*\([^)]*(admin|isAdmin|superuser|root)[^)]*\)`)

	// --- feature flags ---
	reFeatureToken  = regexp.MustCompile(`(?i)\b(FEATURE_[A-Z0-9_]{3,64}|FLAG_[A-Z0-9_]{3,64})\b`)
	reFlagAssign    = regexp.MustCompile(`(?is)\b(flags?|featureFlags?|toggles?)\s*[:=]\s*\{[^}]{0,600}\}`)
	reEnableDisable = regexp.MustCompile(`(?i)\b(enable|enabled|disable|disabled)\s*[_-]?\s*([a-z0-9_]{3,48})\b`)

	// --- env vars ---
	reProcEnv       = regexp.MustCompile(`\bprocess\.env\.([A-Z0-9_]{2,64})\b`)
	reImportMetaEnv = regexp.MustCompile(`\bimport\.meta\.env\.([A-Z0-9_]{2,64})\b`)
	rePublicEnv     = regexp.MustCompile(`\b(NEXT_PUBLIC_[A-Z0-9_]{2,64}|VITE_[A-Z0-9_]{2,64}|REACT_APP_[A-Z0-9_]{2,64})\b`)

	// --- hardcoded hosts / URLs ---
	reURL            = regexp.MustCompile(`(?i)\b(https?|wss?)://[a-z0-9._-]+(?::\d{2,5})?(?:/[^\s"'<>]{0,200})?`)
	reInternalDomain = regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9-]{3,})\.(local|lan|internal|intra|corp|home|test)\b`)
	reRFC1918        = regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})(?::\d{2,5})?\b`)
)

type JSEndpoint struct {
	Path   string
	Method string
	Kind   string // "fetch", "axios", "xhr", "literal"
}

func Learn(ent *knowledge.Entity, sourceURL string, body []byte) []JSEndpoint {
	if ent == nil {
		return nil
	}
	if ent.Content.JSFindings == nil {
		ent.Content.JSFindings = make(map[string]int)
	}

	s := string(body)

	// We dedupe endpoints by method|path
	seenEP := make(map[string]bool)
	out := make([]JSEndpoint, 0)

	// ----------------------------
	// Secrets / keys
	// ----------------------------
	if rePEM.FindStringIndex(s) != nil {
		ent.Tag(knowledge.SigSensitiveKeyword)
		ent.Content.JSFindings["pem"]++
		appendLeak(ent, "pem", sourceURL, "private_key", "-----BEGIN PRIVATE KEY-----")
	}

	aws := reAWS.FindAllString(s, -1)
	if len(aws) > 0 {
		ent.Tag(knowledge.SigSensitiveKeyword)
		ent.Content.JSFindings["aws_key"] += len(aws)
		for i := 0; i < len(aws) && i < 5; i++ {
			appendLeak(ent, "aws_key", sourceURL, "access_key_id", aws[i])
		}
	}

	jwts := reJWT.FindAllString(s, -1)
	if len(jwts) > 0 {
		ent.Tag(knowledge.SigSensitiveKeyword)
		ent.Content.JSFindings["jwt"] += len(jwts)
		for i := 0; i < len(jwts) && i < 5; i++ {
			appendLeak(ent, "jwt", sourceURL, "", jwts[i])
		}
	}

	assigns := reAssign.FindAllStringSubmatch(s, -1)
	if len(assigns) > 0 {
		ent.Tag(knowledge.SigSensitiveKeyword)
		ent.Content.JSFindings["keyword"] += len(assigns)
		for i := 0; i < len(assigns) && i < 5; i++ {
			key := strings.ToLower(assigns[i][1])
			val := redact(assigns[i][2], 200)
			appendLeak(ent, "keyword", sourceURL, key, val)
		}
	}

	if strings.Contains(s, "authDomain") &&
		strings.Contains(s, "projectId") &&
		strings.Contains(s, "apiKey") {
		ent.Content.JSFindings["firebase"]++
		appendLeak(ent, "firebase", sourceURL, "firebase_config", "Firebase configuration block detected")
	}

	// ----------------------------
	// Endpoint discovery
	// ----------------------------
	endpointCount := 0

	// fetch(...)
	for _, m := range reFetch.FindAllStringSubmatch(s, -1) {
		if addJSEndpoint(&out, seenEP, "GET", m[1], "fetch") {
			endpointCount++
		}
	}

	// axios.<method>(...)
	for _, m := range reAxios.FindAllStringSubmatch(s, -1) {
		method := strings.ToUpper(m[1])
		path := m[2]
		if addJSEndpoint(&out, seenEP, method, path, "axios") {
			endpointCount++
		}
	}

	// xhr.open("METHOD", "path")
	for _, m := range reXHR.FindAllStringSubmatch(s, -1) {
		method := strings.ToUpper(m[1])
		path := m[2]
		if addJSEndpoint(&out, seenEP, method, path, "xhr") {
			endpointCount++
		}
	}

	// interesting string literals
	for _, m := range rePathLiteral.FindAllStringSubmatch(s, -1) {
		if addJSEndpoint(&out, seenEP, "GET", m[1], "literal") {
			endpointCount++
		}
	}

	if endpointCount > 0 {
		ent.Content.JSFindings["endpoint"] += endpointCount
	}

	// ----------------------------
	// Roles / privilege surfaces
	// ----------------------------
	roleHits := reRoleCompare.FindAllStringSubmatch(s, -1)
	if len(roleHits) > 0 {
		ent.Content.JSFindings["role_check"] += len(roleHits)
		for i := 0; i < len(roleHits) && i < 5; i++ {
			appendLeak(ent, "role_check", sourceURL, "role", roleHits[i][2])
		}
	}

	adminBool := reAdminBool.FindAllStringSubmatch(s, -1)
	if len(adminBool) > 0 {
		ent.Content.JSFindings["priv_flag"] += len(adminBool)
		for i := 0; i < len(adminBool) && i < 5; i++ {
			appendLeak(ent, "priv_flag", sourceURL, adminBool[i][1], adminBool[i][2])
		}
	}

	if rePrivGate.FindStringIndex(s) != nil {
		ent.Content.JSFindings["priv_gate"]++
		appendLeak(ent, "priv_gate", sourceURL, "if_gate", "Privilege gate conditional detected")
	}

	// ----------------------------
	// Feature flags
	// ----------------------------
	flags := reFeatureToken.FindAllString(s, -1)
	if len(flags) > 0 {
		ent.Content.JSFindings["feature_token"] += len(flags)
		for i := 0; i < len(flags) && i < 8; i++ {
			appendLeak(ent, "feature_token", sourceURL, "flag", flags[i])
		}
	}

	flagBlocks := reFlagAssign.FindAllString(s, -1)
	if len(flagBlocks) > 0 {
		ent.Content.JSFindings["feature_block"] += len(flagBlocks)
		appendLeak(ent, "feature_block", sourceURL, "flags", "Feature flag object detected")
	}

	enDis := reEnableDisable.FindAllStringSubmatch(s, -1)
	if len(enDis) > 0 {
		ent.Content.JSFindings["feature_toggle"] += len(enDis)
		for i := 0; i < len(enDis) && i < 8; i++ {
			appendLeak(ent, "feature_toggle", sourceURL, enDis[i][1], enDis[i][2])
		}
	}

	// ----------------------------
	// Env vars
	// ----------------------------
	procEnv := reProcEnv.FindAllStringSubmatch(s, -1)
	if len(procEnv) > 0 {
		ent.Content.JSFindings["env_ref"] += len(procEnv)
		for i := 0; i < len(procEnv) && i < 10; i++ {
			appendLeak(ent, "env_ref", sourceURL, "process.env", procEnv[i][1])
		}
	}

	metaEnv := reImportMetaEnv.FindAllStringSubmatch(s, -1)
	if len(metaEnv) > 0 {
		ent.Content.JSFindings["env_ref"] += len(metaEnv)
		for i := 0; i < len(metaEnv) && i < 10; i++ {
			appendLeak(ent, "env_ref", sourceURL, "import.meta.env", metaEnv[i][1])
		}
	}

	pubEnv := rePublicEnv.FindAllString(s, -1)
	if len(pubEnv) > 0 {
		ent.Content.JSFindings["env_public"] += len(pubEnv)
		for i := 0; i < len(pubEnv) && i < 10; i++ {
			appendLeak(ent, "env_public", sourceURL, "public_env", pubEnv[i])
		}
	}

	// ----------------------------
	// Hardcoded hosts / internal infra
	// ----------------------------
	urls := reURL.FindAllString(s, -1)
	for _, u := range urls {
		if isNoiseURL(u) {
			continue
		}
		ent.Content.JSFindings["host_url"]++
		if len(ent.Content.JSLeaks) < 8 {
			appendLeak(ent, "host_url", sourceURL, "url", redact(u, 180))
		}
	}

	internalDomains := reInternalDomain.FindAllStringSubmatch(s, -1)
	if len(internalDomains) > 0 {
		for _, m := range internalDomains {
			label := m[1]
			if label != strings.ToLower(label) {
				continue // camelCase/PascalCase = code identifier, not a hostname
			}
			ent.Content.JSFindings["host_internal"]++
			if len(ent.Content.JSLeaks) < 8 {
				appendLeak(ent, "host_internal", sourceURL, "domain", m[0])
			}
		}
	}

	privIPs := reRFC1918.FindAllString(s, -1)
	if len(privIPs) > 0 {
		ent.Content.JSFindings["host_private_ip"] += len(privIPs)
		for i := 0; i < len(privIPs) && i < 8; i++ {
			appendLeak(ent, "host_private_ip", sourceURL, "ip", privIPs[i])
		}
	}

	return out
}

func addJSEndpoint(out *[]JSEndpoint, seen map[string]bool, method, rawPath, kind string) bool {
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
	return true
}

func appendLeak(ent *knowledge.Entity, kind, source, key, value string) {

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

func redact(s string, max int) string {
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
func isNoiseURL(u string) bool {
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
