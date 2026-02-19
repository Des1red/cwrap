package api

import (
	"cwrap/internal/model"
	"cwrap/internal/recon/behavior"
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/recon/transport"
)

type Engine struct {
	k *knowledge.Knowledge
}

func New() *Engine {
	return &Engine{}
}

func (e *Engine) Run(req model.Request) error {

	e.k = knowledge.New(req.URL)
	e.learnURLParams(req.URL)

	// -------- baseline request --------
	resp, err := transport.Do(req)
	if err != nil {
		return err
	}

	body, err := transport.ReadBody(resp)
	if err != nil {
		return err
	}

	// API interpretation
	e.learn(req.URL, resp, body)

	// -------- behavior engine --------
	b := behavior.New(e.k, interpreter{e})

	err = b.Run(req, req.URL, resp.StatusCode, body)
	if err != nil {
		return err
	}

	// -------- report --------
	e.reportEntity(req.URL)
	return nil
}
