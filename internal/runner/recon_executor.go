package runner

import (
	"cwrap/internal/model"
	"cwrap/internal/recon"
)

type ReconExecutor struct{}

func (ReconExecutor) Run(req model.Request) error {
	return recon.Run(req)
}
