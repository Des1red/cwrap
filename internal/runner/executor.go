package runner

import (
	"cwrap/internal/model"
	"fmt"
)

type Executor interface {
	Run(req model.Request) error
}

func Execute(req model.Request) error {

	targets, err := expandTargets(req)
	if err != nil {
		return err
	}

	for i, t := range targets {

		r := req
		r.URL = t

		exec := resolveExecutor(r)

		fmt.Printf("\n[%d/%d] %s\n", i+1, len(targets), t)

		if err := exec.Run(r); err != nil {
			return err
		}
	}

	return nil
}

func expandTargets(req model.Request) ([]string, error) {
	if req.Flags.Target == "" && req.URL == "" {
		return nil, fmt.Errorf("either URL or --tfile required")
	}
	if req.Flags.Target == "" {
		return []string{req.URL}, nil
	}

	targets, err := readTargets(req.Flags.Target)
	if err != nil {
		return nil, err
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets found in file")
	}

	fmt.Printf("Loaded %d targets from %s\n",
		len(targets),
		req.Flags.Target,
	)

	return targets, nil
}
