package httpintel

import (
	"net/http"
	"testing"
)

// respWithCookies builds a response with one or more Set-Cookie headers,
// preserving order — needed since http.Response.Cookies() parses them
// in the order the headers appear.
func respWithCookies(status int, cookiePairs ...string) *http.Response {
	h := http.Header{}
	for _, c := range cookiePairs {
		h.Add("Set-Cookie", c)
	}
	return &http.Response{StatusCode: status, Header: h}
}

// -------------------------------------------------------
// Header-based tech fingerprinting
// -------------------------------------------------------

func TestLearnTech_ServerHeader(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{"Server": "nginx/1.18.0"}))

	if ent.HTTP.Tech["Server"] != "nginx/1.18.0" {
		t.Errorf("expected Tech[Server]=nginx/1.18.0, got %q", ent.HTTP.Tech["Server"])
	}
}

func TestLearnTech_VercelHeader(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{"X-Vercel-Id": "fra1::4ntpv-1786447108939-f17a7724032b"}))

	if ent.HTTP.Tech["Vercel-Region"] != "Frankfurt, Germany" {
		t.Errorf("expected Tech[Vercel-Region]=Frankfurt, Germany, got %q", ent.HTTP.Tech["Vercel-Region"])
	}
}

func TestLearnTech_VercelUnknownRegionCode(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{"X-Vercel-Id": "xyz9::abc123-1234567890"}))

	if ent.HTTP.Tech["Vercel-Region"] != "xyz9" {
		t.Errorf("expected unresolved region code to pass through raw, got %q", ent.HTTP.Tech["Vercel-Region"])
	}
}

func TestLearnTech_CloudflareHeader(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{"CF-RAY": "7d8f3b2a1c9e4f5d-LAX"}))

	if ent.HTTP.Tech["Cloudflare-Colo"] != "Los Angeles, USA" {
		t.Errorf("expected Tech[Cloudflare-Colo]=Los Angeles, USA, got %q", ent.HTTP.Tech["Cloudflare-Colo"])
	}
}

func TestLearnTech_FastlyHeader(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{"X-Served-By": "cache-lax-kwhr1234-LAX"}))

	if ent.HTTP.Tech["Fastly-POP"] != "Los Angeles, USA" {
		t.Errorf("expected Tech[Fastly-POP]=Los Angeles, USA, got %q", ent.HTTP.Tech["Fastly-POP"])
	}
}

func TestLearnTech_CloudFrontHeader(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{"X-Amz-Cf-Pop": "LAX50-C1"}))

	if ent.HTTP.Tech["CloudFront-POP"] != "Los Angeles, USA" {
		t.Errorf("expected Tech[CloudFront-POP]=Los Angeles, USA, got %q", ent.HTTP.Tech["CloudFront-POP"])
	}
}

func TestLearnTech_UnknownAirportCodeFallsBackRaw(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{"CF-RAY": "7d8f3b2a1c9e4f5d-ZZZ"}))

	if ent.HTTP.Tech["Cloudflare-Colo"] != "ZZZ" {
		t.Errorf("expected unresolved airport code to pass through raw uppercase, got %q", ent.HTTP.Tech["Cloudflare-Colo"])
	}
}
func TestLearnTech_MultipleHeadersCaptured(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{
		"Server":         "Vercel",
		"X-Vercel-Cache": "HIT",
		"X-Powered-By":   "Express",
	}))

	for _, key := range []string{"Server", "X-Vercel-Cache", "X-Powered-By"} {
		if ent.HTTP.Tech[key] == "" {
			t.Errorf("expected Tech[%s] to be populated, got empty", key)
		}
	}
}

func TestLearnTech_NoHeadersNoTech(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, nil))

	if len(ent.HTTP.Tech) != 0 {
		t.Errorf("expected empty Tech map, got %v", ent.HTTP.Tech)
	}
}

// -------------------------------------------------------
// Cookie-based tech fingerprinting
// -------------------------------------------------------

func TestLearnCookieTech_PHPSessionID(t *testing.T) {
	ent := newEnt()
	Learn(ent, respWithCookies(200, "PHPSESSID=abc123; Path=/"))

	if ent.HTTP.Tech["Cookie"] != "PHP" {
		t.Errorf("expected Tech[Cookie]=PHP, got %q", ent.HTTP.Tech["Cookie"])
	}
}

func TestLearnCookieTech_LaravelSession(t *testing.T) {
	ent := newEnt()
	Learn(ent, respWithCookies(200, "laravel_session=xyz789; Path=/; HttpOnly"))

	if ent.HTTP.Tech["Cookie"] != "Laravel" {
		t.Errorf("expected Tech[Cookie]=Laravel, got %q", ent.HTTP.Tech["Cookie"])
	}
}

func TestLearnCookieTech_ExpressConnectSid(t *testing.T) {
	ent := newEnt()
	Learn(ent, respWithCookies(200, "connect.sid=s%3Aabc123; Path=/"))

	if ent.HTTP.Tech["Cookie"] != "Express/Node.js" {
		t.Errorf("expected Tech[Cookie]=Express/Node.js, got %q", ent.HTTP.Tech["Cookie"])
	}
}

func TestLearnCookieTech_DjangoCSRFToken(t *testing.T) {
	ent := newEnt()
	Learn(ent, respWithCookies(200, "csrftoken=abc123def456; Path=/"))

	if ent.HTTP.Tech["Cookie"] != "Django" {
		t.Errorf("expected Tech[Cookie]=Django, got %q", ent.HTTP.Tech["Cookie"])
	}
}

func TestLearnCookieTech_CaseInsensitiveCookieName(t *testing.T) {
	ent := newEnt()
	Learn(ent, respWithCookies(200, "PHPSESSID=abc123; Path=/"))

	if ent.HTTP.Tech["Cookie"] != "PHP" {
		t.Errorf("expected case-insensitive match to still detect PHP, got %q", ent.HTTP.Tech["Cookie"])
	}
}

func TestLearnCookieTech_UnknownCookieNoMatch(t *testing.T) {
	ent := newEnt()
	Learn(ent, respWithCookies(200, "some_custom_cookie=abc123; Path=/"))

	if _, ok := ent.HTTP.Tech["Cookie"]; ok {
		t.Errorf("expected no Cookie tech entry for unrecognized cookie, got %q", ent.HTTP.Tech["Cookie"])
	}
}

func TestLearnCookieTech_MultipleCookiesLastMatchWins(t *testing.T) {
	ent := newEnt()
	// two recognized cookies in the same response — documents the existing
	// unconditional-overwrite behavior (same pattern as the header loop),
	// not a claim that this is the "best" cookie to report.
	Learn(ent, respWithCookies(200,
		"PHPSESSID=abc123; Path=/",
		"laravel_session=xyz789; Path=/",
	))

	if ent.HTTP.Tech["Cookie"] != "Laravel" {
		t.Errorf("expected last-matched cookie (Laravel) to win, got %q", ent.HTTP.Tech["Cookie"])
	}
}

func TestLearnTech_HeaderAndCookieCoexist(t *testing.T) {
	ent := newEnt()

	h := http.Header{}
	h.Set("Server", "nginx/1.18.0")
	h.Set("X-Powered-By", "Express")
	h.Add("Set-Cookie", "laravel_session=xyz789; Path=/")

	Learn(ent, &http.Response{StatusCode: 200, Header: h})

	if ent.HTTP.Tech["Server"] != "nginx/1.18.0" {
		t.Errorf("expected Tech[Server]=nginx/1.18.0, got %q", ent.HTTP.Tech["Server"])
	}
	if ent.HTTP.Tech["X-Powered-By"] != "Express" {
		t.Errorf("expected Tech[X-Powered-By]=Express, got %q", ent.HTTP.Tech["X-Powered-By"])
	}
	if ent.HTTP.Tech["Cookie"] != "Laravel" {
		t.Errorf("expected Tech[Cookie]=Laravel, got %q", ent.HTTP.Tech["Cookie"])
	}
	if len(ent.HTTP.Tech) != 3 {
		t.Errorf("expected exactly 3 Tech entries (Server, X-Powered-By, Cookie), got %d: %v", len(ent.HTTP.Tech), ent.HTTP.Tech)
	}
}
