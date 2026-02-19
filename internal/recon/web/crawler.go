package web

import "cwrap/internal/model"

type Engine struct{}

func New() *Engine { return &Engine{} }

func (e *Engine) Run(req model.Request) error {
	// HTML crawler
	// DOM discovery
	// asset expansion
	return nil
}
