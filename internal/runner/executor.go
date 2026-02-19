package runner

import "cwrap/internal/model"

type Executor interface {
	Run(req model.Request) error
}

func Execute(req model.Request) error {
	exec := resolveExecutor(req)
	return exec.Run(req)
}
