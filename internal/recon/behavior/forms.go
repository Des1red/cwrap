package behavior

import (
	"cwrap/internal/model"
	"cwrap/internal/recon/knowledge"
	"net/url"
	"time"
)

func (e *Engine) requeueForms(base model.Request, rootURL string) {
	root := e.k.Entity(rootURL)

	for _, ent := range e.k.Entities {
		if !ent.SeenSignal(knowledge.SigHasForm) {
			continue
		}

		vals := url.Values{}
		for name, p := range ent.Params {
			if !p.Sources[knowledge.ParamForm] {
				continue
			}
			vals.Set(name, "test")
		}

		if len(vals) == 0 {
			continue
		}

		e.k.PushProbe(root, knowledge.Probe{
			URL:         ent.URL,
			Method:      "POST",
			Body:        []byte(vals.Encode()),
			ContentType: "application/x-www-form-urlencoded",
			Reason:      "form-requeue",
			Priority:    200,
			Created:     time.Now(),
		})
	}
}
