package recon

import (
	"cwrap/internal/model"
	"cwrap/internal/recon/api"
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/recon/report"
	"fmt"
)

type Engine interface {
	Run(req model.Request) (*knowledge.Knowledge, error)
}

func selectEngine(req model.Request) Engine {

	switch req.Flags.Profile {

	case "api":
		return api.New()

	default:
		//return web.New()
		return nil
	}
}

func Run(req model.Request) error {
	engine := selectEngine(req)
	if engine == nil {
		return fmt.Errorf("no recon engine available")
	}

	k, err := engine.Run(req)
	if err != nil {
		return err
	}

	report.Print(k)
	return nil
}
