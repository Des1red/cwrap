package intent

import (
	"cwrap/internal/model"
	"encoding/json"
	"fmt"
)

type sendState struct {
	profile string
	content string
	debug   bool
	data    []kv
}

type kv struct {
	Key   string
	Value any
}

type SendHandler struct{}

func (SendHandler) Translate(args []string) []string {

	tokens := Scan(args)

	var s sendState
	s.data = []kv{}

	var out []Token

	for _, t := range tokens {

		switch t.Type {

		case TokenFlag:
			out = append(out, t)

		case TokenKeyValue:
			var v any = t.Value
			if s.content == "json" {
				v = inferJSONValue(t.Value)
			}
			s.data = append(s.data, kv{t.Key, v})

		case TokenWord:
			if p, ok := IsProfile(t.Value); ok {
				s.profile = p
				continue
			}
			if c, ok := IsContent(t.Value); ok {
				s.content = c
				continue
			}
			out = append(out, t)

		case TokenCookie:
			out = append(out, Token{
				Type: TokenFlag,
				Raw:  "-c\x00" + t.Key + "=" + t.Value,
			})

		case TokenAuth:
			out = append(out, Token{
				Type: TokenFlag,
				Raw:  "-b\x00" + t.Value,
			})
		}
	}

	emitSendBody(&out, &s)
	emitSendModifiers(&out, &s)

	return TokensToArgs(out)
}

func emitSendBody(out *[]Token, s *sendState) {

	if len(s.data) == 0 {
		return
	}

	switch s.content {

	case "json":

		obj := map[string]any{}

		for _, p := range s.data {
			insertJSONPath(obj, p.Key, p.Value)
		}

		j, _ := json.Marshal(obj)
		*out = append(*out, Token{Type: TokenFlag, Raw: "-d\x00" + string(j)})
		*out = append(*out, Token{Type: TokenFlag, Raw: "--as-json"})

	default:

		for _, p := range s.data {
			*out = append(*out, Token{
				Type: TokenFlag,
				Raw:  "-d\x00" + p.Key + "=" + stringify(p.Value),
			})
		}

		*out = append(*out, Token{Type: TokenFlag, Raw: "--as-form"})
	}
}

func stringify(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	default:
		return fmt.Sprint(x)
	}
}

func emitSendModifiers(out *[]Token, s *sendState) {

	if s.profile != "" {
		*out = append(*out, Token{Type: TokenFlag, Raw: "--as\x00" + s.profile})
	}

	if s.debug {
		*out = append(*out, Token{Type: TokenFlag, Raw: "--debug"})
	}
}

func (SendHandler) ApplyDefaults(req *model.Request, f *model.Flags) {
	f.Debug = true
	req.Method = "POST"
}
