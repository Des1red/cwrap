package behavior

import (
	"cwrap/internal/recon/knowledge"
	"net/http"
)

type LearnFunc func(url string, resp *http.Response, body []byte)

// Engine executes active probing and reasoning.
type Engine struct {
	k   *knowledge.Knowledge
	int Interpreter
}

func New(k *knowledge.Knowledge, i Interpreter) *Engine {
	return &Engine{
		k:   k,
		int: i,
	}
}
