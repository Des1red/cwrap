package flags

import (
	"cwrap/internal/model"
	"strings"
)

func normalizeForms(f *model.Flags, r rawInput) {

	for _, fval := range r.forms {

		parts := strings.SplitN(fval, "=", 2)
		if len(parts) != 2 {
			continue
		}

		field := model.FormField{Key: strings.TrimSpace(parts[0])}
		v := strings.TrimSpace(parts[1])

		if strings.HasPrefix(v, "@") {
			field.IsFile = true
			v = v[1:]
		}

		if i := strings.Index(v, ";"); i != -1 {
			field.Value = v[:i]
			field.Extra = v[i:]
		} else {
			field.Value = v
		}

		applyFormModifiers(f, &field)
		f.Form = append(f.Form, field)
	}
}

func applyFormModifiers(f *model.Flags, field *model.FormField) {

	// image helper (consumed once, applies to next file)
	if field.IsFile && f.AsImage != "" {

		ext := f.AsImage
		mime := "image/" + ext

		if ext == "jpeg" || ext == "jpg" {
			ext = "jpg"
			mime = "image/jpeg"
		}

		if !strings.Contains(field.Extra, "filename=") {
			field.Extra += ";filename=image." + ext
		}

		if !strings.Contains(field.Extra, "type=") {
			field.Extra += ";type=" + mime
		}

		f.AsImage = "" // consume
	}

	// filename override (consumed once, applies to next file)
	if field.IsFile && f.Filename != "" {
		if !strings.Contains(field.Extra, "filename=") {
			field.Extra += ";filename=" + f.Filename
		}
		f.Filename = "" // consume
	}
}
