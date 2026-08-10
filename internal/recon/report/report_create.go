package report

import (
	"cwrap/internal/recon/knowledge"
	"cwrap/internal/recon/report/abnormal"
	"cwrap/internal/recon/report/common"
	"fmt"
)

// CreateFileReport writes the full report (tree + deep per-entity analysis) to a file.
// No hidden data, no exceptions.
func createReport(
	k *knowledge.Knowledge,
	debug bool,
) (string, error) {
	if k == nil {
		return "", fmt.Errorf("nil knowledge")
	}

	if err := common.EnsureDir(); err != nil {
		return "", err
	}

	f, path, err := common.CreateFile(k)
	if err != nil {
		return "", err
	}

	writeFullReport(f, k, debug)

	if err := f.Close(); err != nil {
		return path, fmt.Errorf("close report file: %w", err)
	}

	if _, _, err := abnormal.WriteAbnormalResponses(k, path); err != nil {
		return path, err
	}

	return path, nil
}
