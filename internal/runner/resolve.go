package runner

import "cwrap/internal/model"

func resolveExecutor(req model.Request) Executor {

	switch req.Original {

	case "recon":
		return ReconExecutor{}

	case "exploit":
		return ExploitExecutor{}

	default:
		return CurlExecutor{}
	}
}
