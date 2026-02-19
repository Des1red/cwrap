package recon

import (
	"cwrap/internal/model"
	"cwrap/internal/recon/api"
	"cwrap/internal/recon/web"
)

type Engine interface {
	Run(req model.Request) error
}

func selectEngine(req model.Request) Engine {

	switch req.Flags.Profile {

	case "api":
		return api.New()

	default:
		return web.New()
	}
}

func Run(req model.Request) error {
	engine := selectEngine(req)
	return engine.Run(req)
}
