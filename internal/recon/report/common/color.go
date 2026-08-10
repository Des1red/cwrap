package common

import "os"

// ANSI color codes for terminal output only. These helpers are used
// exclusively by the terminal summary (printSummary → os.Stdout) — the
// file report writers never import this file, so escape codes can never
// leak into a saved .report file.
const (
	colorReset = "\x1b[0m"
	colorBold  = "\x1b[1m"
	colorRed   = "\x1b[31m"
	colorGreen = "\x1b[32m"
	colorCyan  = "\x1b[36m"
)

// colorEnabled is computed once at startup: disabled if NO_COLOR is set
// (https://no-color.org) or if stdout isn't an interactive terminal
// (piped, redirected into a file, or captured by `go test`).
var colorEnabled = computeColorEnabled()

func computeColorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func colorize(code, s string) string {
	if !colorEnabled {
		return s
	}
	return code + s + colorReset
}

func Bold(s string) string  { return colorize(colorBold, s) }
func Red(s string) string   { return colorize(colorRed, s) }
func Green(s string) string { return colorize(colorGreen, s) }
func Cyan(s string) string  { return colorize(colorCyan, s) }
