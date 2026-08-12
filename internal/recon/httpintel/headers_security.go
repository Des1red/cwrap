package httpintel

import (
	"cwrap/internal/recon/knowledge"
	"net/http"
	"strings"
)

// securityHeaders are the hardening headers whose absence is worth
// flagging. Case doesn't matter — http.Header.Get canonicalizes it.
var securityHeaders = []string{
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Strict-Transport-Security",
}

// learnSecurityHeaders records which hardening headers are absent from
// HTML-serving responses, and separately flags a frame-ancestors directive
// that's present but permissive. Gated to HTML only: none of this is
// meaningful on a JSON API response.
func learnSecurityHeaders(ent *knowledge.Entity, resp *http.Response) {
	if !ent.Content.LooksLikeHTML {
		return
	}

	csp := resp.Header.Get("Content-Security-Policy")
	frameAncestors, hasFrameAncestors := cspFrameAncestorsValue(csp)

	var missing []string
	for _, h := range securityHeaders {
		if resp.Header.Get(h) != "" {
			continue
		}

		// X-Frame-Options has a modern equivalent: CSP's frame-ancestors
		// directive. Its mere presence — any value — suppresses the
		// missing-XFO warning, since the server made a deliberate
		// clickjacking-policy choice either way. Whether that choice was
		// a *good* one is judged separately below, via
		// SigPermissiveFrameAncestors, not folded into this check.
		if h == "X-Frame-Options" && hasFrameAncestors {
			continue
		}

		missing = append(missing, h)
	}

	if len(missing) > 0 {
		ent.HTTP.MissingSecurityHeaders = missing
		ent.Tag(knowledge.SigMissingSecurityHeaders)
	}

	if hasFrameAncestors {
		ent.HTTP.FrameAncestors = frameAncestors
		if frameAncestorsIsPermissive(frameAncestors) {
			ent.Tag(knowledge.SigPermissiveFrameAncestors)
		}
	}
}

// cspFrameAncestorsValue extracts the frame-ancestors directive's raw
// source-list value from a Content-Security-Policy header, e.g. for
// "default-src 'self'; frame-ancestors 'self' https://trusted.example"
// it returns "'self' https://trusted.example". ok is false if the
// directive isn't present at all.
func cspFrameAncestorsValue(csp string) (value string, ok bool) {
	if csp == "" {
		return "", false
	}

	for _, directive := range strings.Split(csp, ";") {
		directive = strings.TrimSpace(directive)
		if directive == "" {
			continue
		}

		fields := strings.Fields(directive)
		if len(fields) == 0 {
			continue
		}

		if strings.EqualFold(fields[0], "frame-ancestors") {
			return strings.Join(fields[1:], " "), true
		}
	}

	return "", false
}

// frameAncestorsIsPermissive reports whether a frame-ancestors source list
// allows framing broadly enough to be a meaningful clickjacking risk.
// A bare "*" is the clear case: any origin may frame the page.
//
// Caveat: this does not evaluate scheme-wildcard sources (e.g.
// "https://*.example.com" or "https://*") as permissive — those restrict
// to a single registrable domain or scheme and are a materially different,
// narrower risk than an unrestricted "*". Flagging only the unambiguous
// case avoids false positives on legitimately scoped wildcard subdomains;
// broader wildcard-source analysis would be a separate, deliberate
// extension of this check, not an oversight to silently expand later.
func frameAncestorsIsPermissive(value string) bool {
	for _, token := range strings.Fields(value) {
		if token == "*" {
			return true
		}
	}
	return false
}
