package http

import (
	"cwrap/internal/model"
	"cwrap/internal/recon/behavior"
	"cwrap/internal/recon/knowledge"
	"time"
)

type Engine struct {
	k           *knowledge.Knowledge
	dumpSecrets bool
}

func New() *Engine {
	return &Engine{}
}

func (e *Engine) Run(req model.Request) (*knowledge.Knowledge, error) {

	e.k = knowledge.New(req.URL)

	b := behavior.New(e.k, interpreter{e}, req.Flags.Debug)

	err := b.Run(req, req.URL)
	if err != nil {
		return nil, err
	}

	return e.k, nil
}

func (e *Engine) enqueueFormProbe(ent *knowledge.Entity, url string, method string) {

	p := knowledge.Probe{
		URL:      url,
		Method:   method,
		Reason:   "form-action",
		Priority: 60, // higher than generic links
		Created:  time.Now(),
	}

	ent.ProbeQueue.Push(p)
}
