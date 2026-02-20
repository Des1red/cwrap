package report

import "fmt"

const (
	reset = "\033[0m"
	bold  = "\033[1m"

	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	blue   = "\033[34m"
	cyan   = "\033[36m"
	gray   = "\033[90m"
)

func section(name string) {
	fmt.Println(bold + blue + "[" + name + "]" + reset)
}

func good(msg string) {
	fmt.Println(" " + green + "✔ " + msg + reset)
}

func warn(msg string) {
	fmt.Println(" " + yellow + "⚠ " + msg + reset)
}

func bad(msg string) {
	fmt.Println(" " + red + "✖ " + msg + reset)
}

func info(msg string) {
	fmt.Println(" " + cyan + "• " + msg + reset)
}
