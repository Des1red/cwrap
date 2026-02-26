package recon

import (
	"cwrap/internal/model"
	"cwrap/internal/recon/api"
	"cwrap/internal/recon/http"
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

	case "http", "web":
		return http.New()

	default:
		return http.New()
	}
}
func Run(req model.Request) error {
	engine := selectEngine(req)
	if req.Flags.Debug {
		fmt.Printf("Selected recon engine: %T\n", engine)
	}
	if engine == nil {
		return fmt.Errorf("no recon engine available")
	}

	k, err := engine.Run(req)
	if err != nil {
		return err
	}

	report.CreateSummary(k)
	return nil
}
