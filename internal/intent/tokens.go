package intent

import "strings"

type TokenType int

const (
	TokenWord TokenType = iota
	TokenKeyValue
	TokenFlag
	TokenCookie
	TokenAuth
)

type Token struct {
	Type  TokenType
	Key   string
	Value string
	Raw   string
}

func Scan(args []string) []Token {

	var out []Token

	for i := 0; i < len(args); i++ {
		a := args[i]

		// ----- flags -----
		if strings.HasPrefix(a, "-") {

			// flags that consume next argument
			switch a {
			case "-d", "-j", "-f", "-h", "-c", "-b", "--as", "--proxy":
				if i+1 < len(args) {
					out = append(out, Token{
						Type: TokenFlag,
						Raw:  a + "\x00" + args[i+1],
					})
					i++ // consume value
					continue
				}
			}

			out = append(out, Token{Type: TokenFlag, Raw: a})
			continue
		}

		// ----- cookie:key=value -----
		lower := strings.ToLower(a)
		if strings.HasPrefix(lower, "cookie:") || strings.HasPrefix(lower, "cookies:") {

			kv := a[strings.Index(a, ":")+1:]

			if j := strings.Index(kv, "="); j != -1 {
				out = append(out, Token{
					Type:  TokenCookie,
					Key:   kv[:j],
					Value: kv[j+1:],
					Raw:   kv,
				})
				continue
			}
		}

		// ----- bearer/auth/token -----
		if strings.HasPrefix(lower, "bearer=") ||
			strings.HasPrefix(lower, "auth=") ||
			strings.HasPrefix(lower, "token=") {

			j := strings.Index(a, "=")

			out = append(out, Token{
				Type:  TokenAuth,
				Value: a[j+1:],
				Raw:   a,
			})
			continue
		}

		// ----- key=value -----
		if j := strings.Index(a, "="); j != -1 {
			out = append(out, Token{
				Type:  TokenKeyValue,
				Key:   strings.ToLower(a[:j]),
				Value: a[j+1:],
				Raw:   a,
			})
			continue
		}

		// ----- word -----
		out = append(out, Token{
			Type:  TokenWord,
			Value: strings.ToLower(a),
			Raw:   a,
		})
	}

	return out
}

func TokensToArgs(tokens []Token) []string {

	var out []string

	for _, t := range tokens {

		if t.Type == TokenFlag && strings.Contains(t.Raw, "\x00") {
			parts := strings.SplitN(t.Raw, "\x00", 2)
			out = append(out, parts[0], parts[1])
			continue
		}

		out = append(out, t.Raw)
	}

	return out
}
