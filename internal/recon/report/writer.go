package report

import (
	"os"
	"path/filepath"
	"time"
)

func WriteToFile(content string) error {

	now := time.Now()
	dir := "reports"

	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return err
	}

	filename := now.Format("2006-01-02_15-04-05") + ".report"
	fullPath := filepath.Join(dir, filename)

	return os.WriteFile(fullPath, []byte(content), 0644)
}
