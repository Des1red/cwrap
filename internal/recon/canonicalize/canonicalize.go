package canonicalize

import (
	"encoding/json"
	"regexp"
	"strings"
)

// JSON normalizes a JSON body for structural comparison.
// All leaf values are replaced with typed placeholders so that two responses
// with the same schema but different data compare equal, while responses with
// genuinely different schemas (different keys, types, nesting depth) compare
// different.
//
// Arrays are collapsed to a single-element representation — a list of 3 users
// and a list of 10 users have the same schema and should compare equal.
//
// The param argument is accepted for interface compatibility but unused —
// we normalize all values, not just one key.
func JSON(data []byte, param string) ([]byte, error) {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return json.Marshal(normalizeValue(v))
}

func normalizeValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, sub := range val {
			out[k] = normalizeValue(sub)
		}
		return out
	case []any:
		if len(val) == 0 {
			return []any{}
		}
		// collapse to first element only —
		// list length is not a schema difference
		return []any{normalizeValue(val[0])}
	case string:
		return "<string>"
	case float64:
		return "<number>"
	case bool:
		return "<bool>"
	case nil:
		return nil
	default:
		return "<unknown>"
	}
}

// HTML normalizes an HTML body for structural comparison.
// Strips script/style content, attribute values, and text node content,
// keeping only the tag structure and attribute names. Two pages with the
// same DOM structure but different dynamic content compare equal.
func HTML(data []byte) []byte {
	s := string(data)

	// strip script content — may contain dynamic tokens, timestamps etc.
	s = reScript.ReplaceAllString(s, "<script/>")

	// strip style content
	s = reStyle.ReplaceAllString(s, "<style/>")

	// strip attribute values — keep attribute names only
	// e.g. href="..." becomes href=""
	s = reAttrVal.ReplaceAllString(s, `$1=""`)

	// strip text node content — dynamic data lives here
	s = reTextNode.ReplaceAllString(s, `><`)

	// collapse whitespace
	s = reSpace.ReplaceAllString(strings.TrimSpace(s), " ")

	return []byte(s)
}

var (
	reScript   = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	reStyle    = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	reAttrVal  = regexp.MustCompile(`(?i)\s([\w-]+)="[^"]*"`)
	reTextNode = regexp.MustCompile(`>([^<]+)<`)
	reSpace    = regexp.MustCompile(`\s+`)
)

// StripNumbers is a last-resort fallback for unknown content types.
// Replaces all digit characters with '#' to remove numeric noise before
// byte comparison.
func StripNumbers(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	for i := range out {
		if out[i] >= '0' && out[i] <= '9' {
			out[i] = '#'
		}
	}
	return out
}
