package report

import (
	"fmt"
	"io"
	"strings"
)

type reportWriter struct {
	w io.Writer
}

func (rw reportWriter) line(indent int, format string, args ...any) {
	prefix := strings.Repeat(" ", indent)
	fmt.Fprintf(rw.w, prefix+format+"\n", args...)
}

func (rw reportWriter) blank() {
	fmt.Fprintln(rw.w)
}

func joinSpace(parts []string) string {
	return strings.Join(parts, " ")
}
