package intent

import "cwrap/internal/model"

type ScanHandler struct {
	cookies []model.Cookie
	bearer  string
	profile string
}

func (h *ScanHandler) Translate(args []string) []string {
	tokens := Scan(args)
	var out []Token
	for _, t := range tokens {
		switch t.Type {
		case TokenWord:
			if p, ok := isProfile(t.Value); ok {
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
	return TokensToArgs(out)
}

func (h *ScanHandler) ApplyDefaults(req *model.Request, f *model.Flags) {
	req.Method = "GET"

	if f.DirWordlist != "" {
		req.FilePath = f.DirWordlist
	}
	if f.DomainWordlist != "" {
		req.SubdomainFile = f.DomainWordlist
	}
	if h.profile != "" {
		f.Profile = h.profile
	}
	if len(h.cookies) > 0 {
		f.Cookies = append(f.Cookies, h.cookies...)
	}
	if h.bearer != "" {
		f.Bearer = h.bearer
	}
}
