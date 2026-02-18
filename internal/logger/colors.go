package logger

const (
	reset  = "\033[0m"
	green  = "\033[32m"
	purple = "\033[35m"
)

func key(s string) string {
	return purple + s + reset
}

func val(s string) string {
	return green + s + reset
}
