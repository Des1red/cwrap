package http

import (
	"cwrap/internal/recon/canonicalize"
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/recon/paramintel"
	"net/http"
)

type interpreter struct {
	e *Engine
}

func (i interpreter) Learn(url string, resp *http.Response, body []byte) {
	i.e.learn(url, resp, body)
}

// Canonicalize normalizes a response body for structural comparison.
// Detects content type from the body itself rather than relying on entity
// state, since this is called inline during analysis.
//
// JSON bodies: all leaf values replaced with typed placeholders — schema
// comparison only, value differences ignored.
//
// HTML bodies: script/style content stripped, attribute values and text
// nodes cleared — tag structure and attribute names preserved.
//
// Unknown: digit stripping as a last-resort structural approximation.
func (i interpreter) Canonicalize(body []byte, param string) ([]byte, error) {
	if looksLikeJSONBody(body) {
		return canonicalize.JSON(body, param)
	}
	if looksLikeHTMLBody(body) {
		return canonicalize.HTML(body), nil
	}
	return canonicalize.StripNumbers(body), nil
}

func (i interpreter) ClassifyParam(ent *knowledge.Entity, name string) {
	p, ok := ent.Params[name]
	if !ok {
		return
	}
	paramintel.ClassifyParam(ent, p)
}
