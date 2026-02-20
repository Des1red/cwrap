package api

import (
	"cwrap/internal/model"
	"cwrap/internal/recon/behavior"
	"cwrap/internal/recon/knowledge"
)

type Engine struct {
	k *knowledge.Knowledge
}

func New() *Engine {
	return &Engine{}
}

func (e *Engine) Run(req model.Request) (*knowledge.Knowledge, error) {

	e.k = knowledge.New(req.URL)
	e.learnURLParams(req.URL)

	b := behavior.New(e.k, interpreter{e})

	err := b.Run(req, req.URL)
	if err != nil {
		return nil, err
	}

	return e.k, nil
}
