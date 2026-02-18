package intent

import (
	"cwrap/internal/model"
	"os"
)

type uploadState struct {
	profile string
	debug   bool
	hasFile bool
}

type UploadHandler struct{}

func (UploadHandler) Translate(args []string) []string {

	tokens := Scan(args)

	var s uploadState
	var out []Token

	for _, t := range tokens {

		switch t.Type {

		case TokenFlag:
			out = append(out, t)

		case TokenKeyValue:
			out = append(out, Token{
				Type: TokenFlag,
				Raw:  "-f\x00" + t.Key + "=" + t.Value,
			})

		case TokenWord:
			if p, ok := IsProfile(t.Value); ok {
				s.profile = p
				continue
			}
			// content modifiers forbidden
			if _, ok := IsContent(t.Value); ok {
				println("cwrap: upload only supports multipart form — remove 'json/form/xml'")
				os.Exit(1)
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

	emitUploadModifiers(&out, &s)

	return TokensToArgs(out)
}

func emitUploadModifiers(out *[]Token, s *uploadState) {

	if s.profile != "" {
		*out = append(*out, Token{Type: TokenFlag, Raw: "--as\x00" + s.profile})
	}

	// semantic commands always preview
	*out = append(*out, Token{Type: TokenFlag, Raw: "--debug"})
}

func (UploadHandler) ApplyDefaults(req *model.Request, f *model.Flags) {

	f.Debug = true
	req.Method = "POST"

	// forbid non-multipart body
	if f.Body != "" || f.JSON || f.ContentProfile != "" {
		println("cwrap: upload only supports multipart form — use send")
		os.Exit(1)
	}

	// require file
	hasFile := false
	for _, form := range f.Form {
		if form.IsFile {
			hasFile = true
			break
		}
	}

	if !hasFile {
		println("cwrap: upload requires a file field (file=@path)")
		os.Exit(1)
	}
}
