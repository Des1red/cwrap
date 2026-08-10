package common

import (
	"fmt"
	"io"
	"strings"
)

type ReportWriter struct {
	W io.Writer
}

func (rw ReportWriter) Line(indent int, format string, args ...any) {
	prefix := strings.Repeat(" ", indent)
	fmt.Fprintf(rw.W, prefix+format+"\n", args...)
}

func (rw ReportWriter) Blank() {
	fmt.Fprintln(rw.W)
}

func JoinSpace(parts []string) string {
	return strings.Join(parts, " ")
}

// KV prints a left-aligned "key" column of fixed width followed by a
// formatted value, so consecutive fields line up into a readable column.
// key should include its trailing colon, e.g. "Probes:".
func (rw ReportWriter) KV(indent int, width int, key string, format string, args ...any) {
	prefix := strings.Repeat(" ", indent)
	label := fmt.Sprintf("%-*s", width, key)
	fmt.Fprintf(rw.W, prefix+label+format+"\n", args...)
}

func JoinComma(parts []string) string {
	return strings.Join(parts, ", ")
}
