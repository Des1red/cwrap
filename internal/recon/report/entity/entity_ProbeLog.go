package entity

import (
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/recon/report/common"
	"fmt"
	"io"
	"sort"
)

func WriteTaggedProbeLog(w io.Writer, k *knowledge.Knowledge, debug bool) {
	if !debug {
		return
	}
	rw := common.ReportWriter{W: w}

	rw.Line(0, "------------------------------------------------")
	rw.Line(0, "PROBE LOG FOR TAGGED ENTITIES")
	rw.Line(0, "------------------------------------------------")

	printed := false

	for _, u := range entityURLsByRoute(k) {
		ent := k.Entities[u]
		if ent == nil || ent.State.IsSPAFallback {
			continue
		}

		sigs := activeSignals(ent)
		if len(sigs) == 0 || len(ent.ProbeLog) == 0 {
			continue
		}

		rows := make([]knowledge.ProbeLogEntry, 0, len(ent.ProbeLog))
		for _, p := range ent.ProbeLog {
			if shouldPrintProbeLog(p) {
				rows = append(rows, p)
			}
		}

		if len(rows) == 0 {
			continue
		}

		sort.Slice(rows, func(i, j int) bool {
			if rows[i].URL != rows[j].URL {
				return rows[i].URL < rows[j].URL
			}
			if rows[i].Reason != rows[j].Reason {
				return rows[i].Reason < rows[j].Reason
			}
			if rows[i].IdentityKind != rows[j].IdentityKind {
				return rows[i].IdentityKind < rows[j].IdentityKind
			}
			if rows[i].Identity != rows[j].Identity {
				return rows[i].Identity < rows[j].Identity
			}
			if rows[i].Method != rows[j].Method {
				return rows[i].Method < rows[j].Method
			}
			return rows[i].Status < rows[j].Status
		})

		printed = true

		rw.Blank()
		rw.Line(0, "[ENTITY] %s", ent.URL)
		rw.Line(2, "Signals: %v", sigs)

		for _, p := range rows {
			count := ""
			if p.Count > 1 {
				count = fmt.Sprintf(" ×%d", p.Count)
			}

			loc := ""
			if p.Location != "" {
				loc = " -> " + p.Location
			}

			reason := p.Reason
			if kind := probeIdentityKindLabel(p.IdentityKind); kind != "" {
				reason += "/" + kind
			}

			rw.Line(
				2,
				"%-6s %-14s %-3d%s %s [%s]%s",
				p.Method,
				p.Identity,
				p.Status,
				count,
				p.URL,
				reason,
				loc,
			)
		}
	}

	if !printed {
		rw.Line(0, "(no tagged probe log)")
	}

	rw.Blank()
}

func shouldPrintProbeLog(p knowledge.ProbeLogEntry) bool {
	return p.Status != 404 && p.Status < 500
}

func probeIdentityKindLabel(k knowledge.ProbeIdentityKind) string {
	switch k {
	case knowledge.ProbeIdentitySynthetic:
		return "synthetic"
	case knowledge.ProbeIdentityLive:
		return "live"
	default:
		return ""
	}
}
