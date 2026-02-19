package api

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
	return normalizeJSONWithParam(body, param)
}

func (i interpreter) ClassifyParam(ent *knowledge.Entity, name string) {
	classifyParam(ent, ent.Params[name])
}
