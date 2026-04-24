package report

import (
	"cwrap/internal/model"
	"cwrap/internal/recon/knowledge"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CreateFileReport writes the full report (tree + deep per-entity analysis) to a file.
// No hidden data, no exceptions.
func CreateFileReport(k *knowledge.Knowledge) (string, error) {
	if k == nil {
		return "", fmt.Errorf("nil knowledge")
	}
	if err := ensureDir(); err != nil {
		return "", err
	}

	f, path, err := createFile(k)
	if err != nil {
		return "", err
	}
	defer f.Close()

	writeFullReport(f, k)

	return path, nil
}

// ---- file plumbing ----

func ensureDir() error {
	return os.MkdirAll(model.ReportDirectoryName, 0o755)
}

func createFile(k *knowledge.Knowledge) (*os.File, string, error) {
	targetPart := sanitizeTargetForFilename(k.Target)
	if targetPart == "" {
		targetPart = "target"
	}

	// Local time (your machine / environment timezone). Filename includes date.
	ts := time.Now().Format("2006-01-02_15-04-05")
	name := fmt.Sprintf("%s_%s."+model.ReportExtension, targetPart, ts)
	path := filepath.Join(model.ReportDirectoryName, name)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, "", err
	}
	return f, path, nil
}

func sanitizeTargetForFilename(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	// Drop scheme if present.
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}

	// Cut at first whitespace.
	if i := strings.IndexAny(s, " \t\r\n"); i >= 0 {
		s = s[:i]
	}

	// Replace unsafe filename characters with '-'.
	repl := strings.NewReplacer(
		"/", "-",
		"\\", "-",
		":", "-",
		"?", "-",
		"&", "-",
		"=", "-",
		"#", "-",
		"%", "-",
		"@", "-",
		"+", "-",
		",", "-",
		";", "-",
		"(", "-",
		")", "-",
		"[", "-",
		"]", "-",
		"{", "-",
		"}", "-",
		"\"", "-",
		"'", "-",
		"<", "-",
		">", "-",
		"|", "-",
		"*", "-",
		"!", "-",
	)
	s = repl.Replace(s)

	// Collapse repeats.
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-._")
	return s
}
