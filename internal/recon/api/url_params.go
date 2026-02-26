package api

import (
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/recon/paramintel"
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
		paramintel.ClassifyParam(ent, ent.Params[key])
		ent.Tag(knowledge.SigHasQueryParams)
	}
}
