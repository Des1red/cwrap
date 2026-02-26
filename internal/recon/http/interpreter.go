package http

import (
	"cwrap/internal/recon/knowledge"
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

func (i interpreter) Classify(ent *knowledge.Entity, name string) {
	i.ClassifyParam(ent, name)
}
