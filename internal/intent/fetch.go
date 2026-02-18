package intent

import (
	"cwrap/internal/model"
	"os"
)

type fetchState struct {
	profile string
	content string
	follow  *bool
	debug   bool
}

type FetchHandler struct{}

func (FetchHandler) Translate(args []string) []string {

	tokens := Scan(args)

	var s fetchState
	var out []Token

	followDefault := true
	s.follow = &followDefault

	for _, t := range tokens {

		switch t.Type {

		case TokenFlag:
			out = append(out, t)

		case TokenKeyValue:
			switch t.Key {

			case "follow":
				v := t.Value == "true"
				s.follow = &v

			case "as", "profile":
				if p, ok := IsProfile(t.Value); ok {
					s.profile = p
				}

			case "proxy":
				out = append(out, Token{Type: TokenFlag, Raw: "--proxy\x00" + t.Value})

			default:
				out = append(out, Token{Type: TokenFlag, Raw: "-q\x00" + t.Raw})
			}

		case TokenWord:
			if p, ok := IsProfile(t.Value); ok {
				s.profile = p
				continue
			}
			if _, ok := IsContent(t.Value); ok {
				println("cwrap: fetch cannot use json/form/xml — use send")
				os.Exit(1)
			}

			if v, ok := IsBooleanWord(t.Value); ok {
				s.follow = &v
				continue
			}

			out = append(out, t)

		case TokenCookie:
			out = append(out, Token{Type: TokenFlag, Raw: "-c\x00" + t.Key + "=" + t.Value})

		case TokenAuth:
			out = append(out, Token{Type: TokenFlag, Raw: "-b\x00" + t.Value})
		}
	}

	emitFetchModifiers(&out, &s)
	return TokensToArgs(out)
}

func emitFetchModifiers(out *[]Token, s *fetchState) {

	if s.profile != "" {
		*out = append(*out, Token{Type: TokenFlag, Raw: "--as\x00" + s.profile})
	}

	if s.follow != nil {
		if *s.follow {
			*out = append(*out, Token{Type: TokenFlag, Raw: "--follow"})
		} else {
			*out = append(*out, Token{Type: TokenFlag, Raw: "--follow=false"})
		}
	}

	if s.debug {
		*out = append(*out, Token{Type: TokenFlag, Raw: "--debug"})
	}
}

func (FetchHandler) ApplyDefaults(req *model.Request, f *model.Flags) {

	// semantic commands always preview
	f.Debug = true

	// fetch is strictly retrieval
	// GET cannot have body semantics
	if f.JSON || f.ContentProfile != "" || f.Body != "" || len(f.Form) > 0 {
		println("cwrap: fetch cannot send data — use send")
		os.Exit(1)
	}

	if f.Head {
		req.Method = "HEAD"
		return
	}

	req.Method = "GET"
}
