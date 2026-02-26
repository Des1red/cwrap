package runner

import (
	"cwrap/internal/model"
	"cwrap/internal/recon"
	"fmt"
)

type ReconExecutor struct{}

func (ReconExecutor) Run(req model.Request) error {

	// single target (current behavior)
	if req.Flags.Target == "" {
		return recon.Run(req)
	}

	// multi target mode
	targets, err := readTargets(req.Flags.Target)
	if err != nil {
		return err
	}

	for _, t := range targets {
		r := req
		r.URL = t

		fmt.Println("\n---", t, "---")

		if err := recon.Run(r); err != nil {
			// - stop on first error:
			return err
		}
	}

	return nil
}
