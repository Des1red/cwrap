package flags

import (
	"cwrap/internal/model"
	"flag"
	"strings"
)

func Parse(args []string) model.Flags {
	var f model.Flags

	var jsonBody string
	var rawHeaders model.MultiValue
	var rawCookies model.MultiValue
	var rawForms model.MultiValue

	fs := flag.NewFlagSet("cwrap", flag.ContinueOnError)

	fs.BoolVar(&f.Run, "run", false, "execute curl")
	fs.StringVar(&f.Profile, "as", "", "request profile (firefox, chrome, api, curl)")
	fs.Var(&rawHeaders, "h", "header")
	fs.Var(&rawCookies, "c", "cookie")
	fs.StringVar(&f.Bearer, "b", "", "bearer token")
	fs.StringVar(&f.Body, "d", "", "request body")
	fs.StringVar(&jsonBody, "j", "", "json body")
	fs.Var(&rawForms, "f", "multipart form field")
	fs.StringVar(&f.Filename, "filename", "", "override uploaded file name")
	fs.StringVar(&f.AsImage, "as-image", "", "treat next file as image (jpeg,png,gif)")

	_ = fs.Parse(args)
	if jsonBody != "" {
		f.Body = jsonBody
		f.JSON = true
	}

	// ---- NORMALIZE ----

	// normalize profile
	f.Profile = strings.ToLower(strings.TrimSpace(f.Profile))
	// normalize headers
	for _, h := range rawHeaders {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			continue
		}
		f.Headers = append(f.Headers, model.Header{
			Name:  strings.TrimSpace(parts[0]),
			Value: strings.TrimSpace(parts[1]),
		})
	}

	// normalize cookies
	for _, c := range rawCookies {
		parts := strings.SplitN(c, "=", 2)
		if len(parts) != 2 {
			continue
		}
		f.Cookies = append(f.Cookies, model.Cookie{
			Name:  strings.TrimSpace(parts[0]),
			Value: strings.TrimSpace(parts[1]),
		})
	}

	// normalize forms
	for _, fval := range rawForms {

		parts := strings.SplitN(fval, "=", 2)
		if len(parts) != 2 {
			continue
		}

		field := model.FormField{
			Key: strings.TrimSpace(parts[0]),
		}

		v := strings.TrimSpace(parts[1])

		// detect file
		if strings.HasPrefix(v, "@") {
			field.IsFile = true
			v = v[1:]
		}

		// split extras first
		if i := strings.Index(v, ";"); i != -1 {
			field.Value = v[:i]
			field.Extra = v[i:]
		} else {
			field.Value = v
		}

		// ---- modifiers applied AFTER parsing ----

		// image helper
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

		// filename override (stronger than helper)
		if field.IsFile && f.Filename != "" {
			if !strings.Contains(field.Extra, "filename=") {
				field.Extra += ";filename=" + f.Filename
			}
			f.Filename = "" // consume
		}

		f.Form = append(f.Form, field)
	}

	return f
}
