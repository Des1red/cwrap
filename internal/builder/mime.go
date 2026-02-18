package builder

import (
	"mime"
	"path/filepath"
)

func detectMime(path string) string {
	ext := filepath.Ext(path)
	if ext == "" {
		return ""
	}

	m := mime.TypeByExtension(ext)
	return m
}
