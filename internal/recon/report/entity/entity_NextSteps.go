package entity

import (
	"cwrap/internal/recon/report/common"
	"cwrap/internal/recon/report/derive"
	"io"
	"sort"
)

func writeGroupNextSteps(w io.Writer, g entityGroup) {
	rw := common.ReportWriter{W: w}

	byStep := map[string][]string{}

	for _, ent := range g.Entities {
		if ent == nil {
			continue
		}

		for _, step := range derive.DeriveNextSteps(ent) {
			byStep[step] = append(byStep[step], ent.URL)
		}
	}

	if len(byStep) == 0 {
		return
	}

	steps := make([]string, 0, len(byStep))
	for step := range byStep {
		steps = append(steps, step)
	}
	sort.Strings(steps)

	rw.Line(2, "Group Next Steps:")
	for _, step := range steps {
		urls := byStep[step]
		sort.Strings(urls)
		urls = common.Dedup(urls)

		rw.Blank()
		rw.Line(4, "> %s", step)
		for _, u := range urls {
			rw.Line(8, "from: %s", u)
		}
	}
}
