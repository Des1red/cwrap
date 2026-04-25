package runner

import (
	"cwrap/internal/model"
	"fmt"
	"net/url"
)

type Executor interface {
	Run(req model.Request) error
}

func Execute(req model.Request) error {

	// recon with --tfile gets special grouped handling
	if req.Original == "recon" && req.Flags.Target != "" {
		return executeReconGrouped(req)
	}

	targets, err := expandTargets(req)
	if err != nil {
		return err
	}

	for i, t := range targets {

		r := req
		if req.FilePath != "" {
			r.FilePath = t
		} else {
			r.URL = t
		}

		exec := resolveExecutor(r)

		fmt.Printf("\n[%d/%d] %s\n", i+1, len(targets), t)

		if err := exec.Run(r); err != nil {
			return err
		}
	}

	return nil
}

func executeReconGrouped(req model.Request) error {
	targets, err := readTargets(req.Flags.Target)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("no targets found in file")
	}

	groups := groupTargetsByHost(targets)
	fmt.Printf("Loaded %d targets from %s (%d host group(s))\n",
		len(targets), req.Flags.Target, len(groups))

	i := 0
	for host, urls := range groups {
		i++
		fmt.Printf("\n[%d/%d] %s (%d endpoint(s))\n", i, len(groups), host, len(urls))
		r := req
		r.URL = host
		r.Flags.SeedURLs = urls
		exec := resolveExecutor(r)
		if err := exec.Run(r); err != nil {
			return err
		}
	}
	return nil
}

func expandTargets(req model.Request) ([]string, error) {
	if req.Flags.Target == "" && req.URL == "" && req.FilePath == "" {
		return nil, fmt.Errorf("either URL/ReportPath or --tfile required")
	}

	if req.FilePath != "" {
		return []string{req.FilePath}, nil
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

func groupTargetsByHost(targets []string) map[string][]string {
	groups := make(map[string][]string)
	for _, t := range targets {
		u, err := url.Parse(t)
		if err != nil {
			groups[t] = append(groups[t], t)
			continue
		}
		key := u.Scheme + "://" + u.Host
		groups[key] = append(groups[key], t)
	}
	return groups
}
