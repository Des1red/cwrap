package logger

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
	Gray   = "\033[90m"
	Bold   = "\033[1m"
	Purple = "\033[35m"
)

func key(s string) string {
	return Purple + s + Reset
}

func val(s string) string {
	return Green + s + Reset
}
