package runner

import (
	"cwrap/internal/model"
	"cwrap/internal/scan"
)

type ScanExecutor struct{}

func (ScanExecutor) Run(req model.Request) error {
	return scan.Run(req)
}
