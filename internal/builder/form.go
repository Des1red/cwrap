package builder

import (
	"cwrap/internal/model"
	"fmt"
	"mime"
	"path/filepath"
	"strings"
)

func buildMultipart(args []string, req model.Request) []string {
	if len(req.Flags.Form) == 0 {
		return args
	}

	for _, f := range req.Flags.Form {

		val := f.Value

		if f.IsFile {

			if !strings.Contains(f.Extra, ";type=") {
				if m := detectMime(f.Value); m != "" {
					f.Extra += ";type=" + m
				}
			}

			val = "@" + val + f.Extra
		} else {
			val += f.Extra
		}

		args = append(args, "-F", fmt.Sprintf("%s=%s", f.Key, val))
	}

	return args
}

func detectMime(path string) string {
	ext := filepath.Ext(path)
	if ext == "" {
		return ""
	}

	m := mime.TypeByExtension(ext)
	return m
}
