package report

import (
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/recon/report/entity"
	"fmt"
	"io"
	"time"
)

func writeFullReport(w io.Writer, k *knowledge.Knowledge, debug bool) {
	now := time.Now().Format("2006-01-02 15:04:05")

	fmt.Fprintln(w, "========== CWRAP FULL RECON REPORT ==========")
	if k.Target != "" {
		fmt.Fprintln(w, "Target:   ", k.Target)
	}
	fmt.Fprintln(w, "Generated:", now)
	fmt.Fprintln(w)

	writeGlobalStats(w, k)
	writeContactInfo(w, k)
	writeDiscoveryTree(w, k)
	writeRouteTree(w, k)
	entity.WriteEntityDetails(w, k)
	entity.WriteUnconfirmedAdminSurfaceRoutes(w, k)
	entity.WriteTaggedProbeLog(w, k, debug)
	writeStaticAssets(w, k)
	writeIdentityVault(w, k)

	fmt.Fprintln(w)
	fmt.Fprintln(w, "=============== END OF REPORT ===============")
}
