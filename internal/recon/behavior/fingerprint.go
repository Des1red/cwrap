package behavior

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/html"
)

type PageFP struct {
	StatusClass int
	ContentKind string
	Location    string
	Title       string
	H1          string
	AssetHash   string
	FormHash    string
	BodyBucket  int
	NormHash    string
}

func fpString(status int, body []byte) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf("%d:%x", status, sum)
}

func buildPageFP(baseURL string, resp *http.Response, body []byte) PageFP {
	fp := PageFP{
		StatusClass: resp.StatusCode / 100,
		ContentKind: contentKind(resp.Header.Get("Content-Type")),
		Location:    normalizeLocation(baseURL, resp.Header.Get("Location")),
		BodyBucket:  len(body) / 512,
		NormHash:    normalizedBodyHash(body),
	}

	if fp.ContentKind != "html" {
		return fp
	}

	title, h1, assets, forms := extractHTMLPageParts(baseURL, body)
	fp.Title = title
	fp.H1 = h1
	fp.AssetHash = stringSetHash(assets)
	fp.FormHash = stringSetHash(forms)

	return fp
}

func looksLikeFallbackPage(a, base PageFP) bool {
	if a.ContentKind != "html" && a.Location == "" {
		return false
	}

	score := 0

	if a.StatusClass == base.StatusClass {
		score += 2
	}
	if a.ContentKind != "" && a.ContentKind == base.ContentKind {
		score += 2
	}
	if a.Location != "" && (a.Location == base.Location || isCommonFallbackLocation(a.Location)) {
		score += 5
	}
	if a.Title != "" && a.Title == base.Title {
		score += 3
	}
	if a.H1 != "" && a.H1 == base.H1 {
		score += 2
	}
	if a.AssetHash != "" && a.AssetHash == base.AssetHash {
		score += 4
	}
	if a.FormHash != "" && a.FormHash == base.FormHash {
		score += 2
	}
	if a.BodyBucket == base.BodyBucket {
		score += 1
	}
	if a.NormHash != "" && a.NormHash == base.NormHash {
		score += 4
	}

	return score >= 7
}

func contentKind(ct string) string {
	ct = strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0]))

	switch {
	case strings.Contains(ct, "html"):
		return "html"
	case strings.Contains(ct, "json"):
		return "json"
	case strings.Contains(ct, "xml"):
		return "xml"
	case strings.Contains(ct, "javascript"):
		return "js"
	case strings.Contains(ct, "css"):
		return "css"
	case strings.HasPrefix(ct, "image/"):
		return "image"
	default:
		return ct
	}
}

func normalizeLocation(baseURL, loc string) string {
	if loc == "" {
		return ""
	}

	u, err := url.Parse(loc)
	if err != nil {
		return strings.TrimSpace(loc)
	}

	if !u.IsAbs() {
		base, err := url.Parse(baseURL)
		if err == nil {
			u = base.ResolveReference(u)
		}
	}

	u.RawQuery = ""
	u.Fragment = ""

	return u.String()
}

func isCommonFallbackLocation(loc string) bool {
	u, err := url.Parse(loc)
	if err != nil {
		return false
	}

	p := strings.ToLower(strings.TrimRight(u.Path, "/"))
	return p == "" ||
		p == "/login" ||
		p == "/home" ||
		p == "/signin" ||
		p == "/sign-in" ||
		p == "/auth/login"
}

func extractHTMLPageParts(baseURL string, body []byte) (title, h1 string, assets, forms []string) {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return "", "", nil, nil
	}

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "title":
				if title == "" {
					title = strings.TrimSpace(htmlNodeText(n))
				}

			case "h1":
				if h1 == "" {
					h1 = strings.TrimSpace(htmlNodeText(n))
				}

			case "script":
				if src := attr(n, "src"); src != "" {
					assets = append(assets, normalizePageURL(baseURL, src))
				}

			case "link":
				rel := strings.ToLower(attr(n, "rel"))
				href := attr(n, "href")
				if href != "" && (strings.Contains(rel, "stylesheet") || strings.Contains(rel, "icon")) {
					assets = append(assets, normalizePageURL(baseURL, href))
				}

			case "form":
				action := attr(n, "action")
				if action == "" {
					action = baseURL
				}
				forms = append(forms, normalizePageURL(baseURL, action))
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}

	walk(doc)
	return title, h1, assets, forms
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return strings.TrimSpace(a.Val)
		}
	}
	return ""
}

func normalizePageURL(baseURL, raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return strings.TrimSpace(raw)
	}

	if !u.IsAbs() {
		base, err := url.Parse(baseURL)
		if err == nil {
			u = base.ResolveReference(u)
		}
	}

	u.RawQuery = ""
	u.Fragment = ""

	return u.String()
}

func stringSetHash(items []string) string {
	if len(items) == 0 {
		return ""
	}

	sort.Strings(items)

	dedup := items[:0]
	var last string
	for i, item := range items {
		if i == 0 || item != last {
			dedup = append(dedup, item)
			last = item
		}
	}

	sum := sha256.Sum256([]byte(strings.Join(dedup, "\n")))
	return fmt.Sprintf("%x", sum)
}

var (
	fpJWTRe    = regexp.MustCompile(`\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	fpUUIDRe   = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	fpHexRe    = regexp.MustCompile(`(?i)\b[0-9a-f]{24,}\b`)
	fpNumberRe = regexp.MustCompile(`\b\d+\b`)
)

func normalizedBodyHash(body []byte) string {
	s := string(body)

	s = fpJWTRe.ReplaceAllString(s, "{jwt}")
	s = fpUUIDRe.ReplaceAllString(s, "{uuid}")
	s = fpHexRe.ReplaceAllString(s, "{hex}")
	s = fpNumberRe.ReplaceAllString(s, "{num}")
	s = strings.Join(strings.Fields(s), " ")

	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum)
}

func htmlNodeText(n *html.Node) string {
	var b strings.Builder

	var walk func(*html.Node)
	walk = func(x *html.Node) {
		if x.Type == html.TextNode {
			b.WriteString(x.Data)
		}

		for c := x.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}

	walk(n)
	return b.String()
}
