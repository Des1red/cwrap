package http

import (
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

func (i interpreter) Canonicalize(body []byte, param string) ([]byte, error) {
	return body, nil // no JSON normalization
}

func (i interpreter) ClassifyParam(ent *knowledge.Entity, name string) {

	p, ok := ent.Params[name]
	if !ok {
		return
	}

	paramintel.ClassifyParam(ent, p)
}
