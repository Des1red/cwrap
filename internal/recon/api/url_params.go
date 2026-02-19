package api

import (
	"cwrap/internal/recon/knowledge"
	"net/url"
)

func (e *Engine) learnURLParams(raw string) {
	u, err := url.Parse(raw)
	if err != nil {
		return
	}

	ent := e.k.Entity(raw)

	for key := range u.Query() {
		ent.AddParam(key, knowledge.ParamQuery)
		e.k.AddParam(key)
		classifyParam(ent, ent.Params[key])
		ent.Tag(knowledge.SigHasQueryParams)
	}
}
