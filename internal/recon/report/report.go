// report/report.go
package report

import (
	"cwrap/internal/recon/knowledge"
	"fmt"
	"os"
)

// CreateSummary prints an executive summary to the terminal and saves a full,
// in-depth tree report to ./reports/<target>_<timestamp>.report.
// The full file report contains ALL collected data (no redaction, no truncation).
func CreateSummary(k *knowledge.Knowledge) (string, error) {
	if k == nil {
		return "", fmt.Errorf("nil knowledge")
	}

	path, err := CreateFileReport(k)
	// Even if file creation fails, still print a summary of what we have.
	printSummary(os.Stdout, k, path, err)

	return path, err
}
