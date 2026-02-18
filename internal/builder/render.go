package builder

import "strings"

func buildString(args []string) string {
	parts := make([]string, len(args))

	for i, a := range args {
		parts[i] = shellEscape(a)
	}

	return "curl " + strings.Join(parts, " ")
}

func shellEscape(s string) string {
	if s == "" {
		return "''"
	}

	// safe characters
	if !strings.ContainsAny(s, " \t\n'\"\\$`!&|;<>(){}[]*?~") {
		return s
	}

	// POSIX single-quote escaping
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
