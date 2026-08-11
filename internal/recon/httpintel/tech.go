package httpintel

import (
	"cwrap/internal/recon/knowledge"
	"net/http"
	"strings"
)

// learnTech fingerprints backend technology and hosting infrastructure from
// well-known response headers and session cookie naming conventions.
func learnTech(ent *knowledge.Entity, resp *http.Response) {
	// Headers that are stable as-is — no rotating trace component to strip.
	techHeaders := []string{
		"Server",
		"X-Powered-By",
		"X-Generator",
		"X-AspNet-Version",
		"X-AspNetMvc-Version",
		"X-Runtime",
		"Via",
		"X-Vercel-Cache",
		"CF-Cache-Status",
		"X-Cache",
		"Fastly-Debug-Digest",
	}
	for _, name := range techHeaders {
		if val := resp.Header.Get(name); val != "" {
			ent.HTTP.Tech[name] = val
		}
	}

	learnInfraTraceHeaders(ent, resp)
	learnCookieTech(ent, resp)
}

// infraTraceRule describes a header that embeds a stable location/region
// code alongside a per-request trace ID that rotates on every single
// request. Storing the raw value makes every probe look like a different
// backend; extract pulls out just the stable code, resolve turns it into
// something human-readable.
type infraTraceRule struct {
	header    string
	outputKey string
	extract   func(raw string) (code string, ok bool)
	resolve   func(code string) string
}

var infraTraceRules = []infraTraceRule{
	{
		// Vercel: "fra1::4ntpv-1786447108939-f17a7724032b"
		// region code before "::", rest is a per-request trace ID.
		header:    "X-Vercel-Id",
		outputKey: "Vercel-Region",
		extract:   extractBeforeDoubleColon,
		resolve:   resolveVercelRegion,
	},
	{
		// Cloudflare: "7d8f3b2a1c9e4f5d-LAX"
		// hex ray ID, then the colo's IATA airport code after the dash.
		header:    "CF-RAY",
		outputKey: "Cloudflare-Colo",
		extract:   extractAfterLastDash,
		resolve:   resolveAirportCode,
	},
	{
		// Fastly: "cache-lax-kwhr1234-LAX"
		// cache node ID with the POP's IATA airport code as the final segment.
		header:    "X-Served-By",
		outputKey: "Fastly-POP",
		extract:   extractAfterLastDash,
		resolve:   resolveAirportCode,
	},
	{
		// CloudFront: "LAX50-C1"
		// IATA airport code prefix, then an internal edge-node suffix.
		header:    "X-Amz-Cf-Pop",
		outputKey: "CloudFront-POP",
		extract:   extractLeadingAirportCode,
		resolve:   resolveAirportCode,
	},
}

func learnInfraTraceHeaders(ent *knowledge.Entity, resp *http.Response) {
	for _, rule := range infraTraceRules {
		raw := resp.Header.Get(rule.header)
		if raw == "" {
			continue
		}
		code, ok := rule.extract(raw)
		if !ok || code == "" {
			continue
		}
		ent.HTTP.Tech[rule.outputKey] = rule.resolve(code)
	}
}

func extractBeforeDoubleColon(raw string) (string, bool) {
	code, _, ok := strings.Cut(raw, "::")
	return code, ok && code != ""
}

func extractAfterLastDash(raw string) (string, bool) {
	idx := strings.LastIndex(raw, "-")
	if idx == -1 || idx == len(raw)-1 {
		return "", false
	}
	return raw[idx+1:], true
}

func extractLeadingAirportCode(raw string) (string, bool) {
	if len(raw) < 3 {
		return "", false
	}
	return raw[:3], true
}

// vercelRegions maps Vercel Edge Network region codes to their location.
var vercelRegions = map[string]string{
	"iad1": "Washington, D.C., USA",
	"sfo1": "San Francisco, USA",
	"pdx1": "Portland, USA",
	"cle1": "Cleveland, USA",
	"gru1": "São Paulo, Brazil",
	"cdg1": "Paris, France",
	"dub1": "Dublin, Ireland",
	"fra1": "Frankfurt, Germany",
	"lhr1": "London, UK",
	"arn1": "Stockholm, Sweden",
	"bom1": "Mumbai, India",
	"hnd1": "Tokyo, Japan",
	"icn1": "Seoul, South Korea",
	"sin1": "Singapore",
	"syd1": "Sydney, Australia",
	"hkg1": "Hong Kong",
	"kix1": "Osaka, Japan",
	"cpt1": "Cape Town, South Africa",
}

func resolveVercelRegion(code string) string {
	if name, ok := vercelRegions[strings.ToLower(code)]; ok {
		return name
	}
	return code
}

// iataAirportCodes is a curated subset of major-metro airport codes used to
// resolve Cloudflare/Fastly/CloudFront edge location codes. Not exhaustive —
// unresolved codes fall through to the raw 3-letter code rather than being
// dropped, since the code itself is still meaningful to anyone who
// recognizes it, and it's a strictly better fallback than silently
// discarding the signal.
var iataAirportCodes = map[string]string{
	"LAX": "Los Angeles, USA",
	"SEA": "Seattle, USA",
	"SFO": "San Francisco, USA",
	"ORD": "Chicago, USA",
	"IAD": "Washington, D.C., USA",
	"ATL": "Atlanta, USA",
	"DFW": "Dallas, USA",
	"MIA": "Miami, USA",
	"JFK": "New York, USA",
	"EWR": "Newark, USA",
	"GRU": "São Paulo, Brazil",
	"LHR": "London, UK",
	"CDG": "Paris, France",
	"FRA": "Frankfurt, Germany",
	"AMS": "Amsterdam, Netherlands",
	"MAD": "Madrid, Spain",
	"ARN": "Stockholm, Sweden",
	"DUB": "Dublin, Ireland",
	"BOM": "Mumbai, India",
	"SIN": "Singapore",
	"HKG": "Hong Kong",
	"NRT": "Tokyo, Japan",
	"HND": "Tokyo, Japan",
	"ICN": "Seoul, South Korea",
	"SYD": "Sydney, Australia",
	"CPT": "Cape Town, South Africa",
}

func resolveAirportCode(code string) string {
	if name, ok := iataAirportCodes[strings.ToUpper(code)]; ok {
		return name
	}
	return strings.ToUpper(code)
}

// cookieTechSignatures maps well-known session cookie names (lowercased) to
// the backend technology that issues them. Cookie names are a more durable
// fingerprint than headers, since CDNs and reverse proxies strip or rewrite
// headers far more often than a framework's default cookie name changes.
var cookieTechSignatures = map[string]string{
	"phpsessid":          "PHP",
	"jsessionid":         "Java",
	"laravel_session":    "Laravel",
	"connect.sid":        "Express/Node.js",
	"asp.net_sessionid":  "ASP.NET",
	"asp.net_sessionid2": "ASP.NET",
	"__cfduid":           "Cloudflare",
	"cf_clearance":       "Cloudflare",
	"csrftoken":          "Django",
	"sessionid":          "Django",
	"rack.session":       "Ruby/Rack",
	"_rails_session":     "Ruby on Rails",
}

func learnCookieTech(ent *knowledge.Entity, resp *http.Response) {
	for _, c := range resp.Cookies() {
		if tech, ok := cookieTechSignatures[strings.ToLower(c.Name)]; ok {
			ent.HTTP.Tech["Cookie"] = tech
		}
	}
}
