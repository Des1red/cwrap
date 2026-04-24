package intent

import "cwrap/internal/model"

type ScanHandler struct {
	cookies []model.Cookie
	bearer  string
}

func (h *ScanHandler) Translate(args []string) []string {
	tokens := Scan(args)
	var out []Token
	for _, t := range tokens {
		switch t.Type {
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
	if len(h.cookies) > 0 {
		f.Cookies = append(f.Cookies, h.cookies...)
	}
	if h.bearer != "" {
		f.Bearer = h.bearer
	}
}
