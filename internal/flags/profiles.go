package flags

import "cwrap/internal/model"

func applyProfiles(f *model.Flags, r rawInput) {

	if r.jsonBody != "" {
		f.Body = r.jsonBody
		f.JSON = true
	}

	switch {
	case r.asJSON:
		f.ContentProfile = "json"
	case r.asForm:
		f.ContentProfile = "form"
	case r.asXML:
		f.ContentProfile = "xml"
	}

	if f.JSON {
		f.ContentProfile = "json"
	}
}
