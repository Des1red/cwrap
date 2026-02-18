package flags

import (
	"cwrap/internal/model"
	"flag"
)

type rawInput struct {
	jsonBody string
	headers  model.MultiValue
	cookies  model.MultiValue
	forms    model.MultiValue
	query    model.MultiValue
	asJSON   bool
	asForm   bool
	asXML    bool
}

func register(fs *flag.FlagSet, f *model.Flags) *rawInput {

	r := &rawInput{}

	fs.BoolVar(&f.Run, "run", false, "execute curl")
	fs.StringVar(&f.Profile, "as", "", "request profile (firefox, chrome, api, curl)")
	fs.Var(&r.headers, "h", "header")
	fs.Var(&r.cookies, "c", "cookie")
	fs.StringVar(&f.Bearer, "b", "", "bearer token")
	fs.StringVar(&f.Body, "d", "", "request body")
	fs.StringVar(&r.jsonBody, "j", "", "json body")
	fs.Var(&r.forms, "f", "multipart form field")
	fs.StringVar(&f.Filename, "filename", "", "override uploaded file name")
	fs.StringVar(&f.AsImage, "as-image", "", "treat next file as image (jpeg,png,gif)")
	fs.BoolVar(&f.Follow, "follow", false, "follow redirects")
	fs.BoolVar(&f.Head, "head", false, "send HEAD request")
	fs.StringVar(&f.Proxy, "proxy", "", "proxy url")
	fs.Var(&r.query, "q", "query parameter key=value")

	fs.BoolVar(&r.asJSON, "as-json", false, "json content profile")
	fs.BoolVar(&r.asForm, "as-form", false, "form content profile")
	fs.BoolVar(&r.asXML, "as-xml", false, "xml content profile")

	fs.BoolVar(&f.Debug, "debug", false, "show interpreted request")

	return r
}
