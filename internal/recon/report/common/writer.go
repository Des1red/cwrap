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
