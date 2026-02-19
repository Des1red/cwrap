package intent

import "cwrap/internal/model"

type ReconHandler struct {
	profile string
	cookies []model.Cookie
	bearer  string
}

func (h *ReconHandler) Translate(args []string) []string {

	tokens := Scan(args)
	var out []Token

	for _, t := range tokens {

		switch t.Type {

		case TokenWord:
			if p, ok := IsProfile(t.Value); ok {
				h.profile = p
				continue
			}
			out = append(out, t)

		case TokenCookie:
			h.cookies = append(h.cookies, model.Cookie{
				Name:  t.Key,
				Value: t.Value,
			})

		case TokenAuth:
			h.bearer = t.Value

		default:
			out = append(out, t)
		}
	}

	// recon always debug
	out = append(out, Token{Type: TokenFlag, Raw: "--debug"})

	return TokensToArgs(out)
}

func (h *ReconHandler) ApplyDefaults(req *model.Request, f *model.Flags) {

	req.Method = "GET"

	// profile
	if h.profile != "" {
		f.Profile = h.profile
	}

	// cookies
	if len(h.cookies) > 0 {
		f.Cookies = append(f.Cookies, h.cookies...)
	}

	// bearer
	if h.bearer != "" {
		f.Bearer = h.bearer
	}
}
