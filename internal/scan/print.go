package scan

import (
	"fmt"
	"os"
	"strings"
)

func printResult(status int, url string, size int64) {
	switch {
	case status == 200:
		fmt.Printf("\033[32m[%d]\033[0m %s", status, url)
	case status == 301 || status == 302 || status == 303:
		fmt.Printf("\033[33m[%d]\033[0m %s", status, url)
	case status == 401 || status == 403:
		fmt.Printf("\033[31m[%d]\033[0m %s", status, url)
	default:
		return
	}
	if size > 0 {
		fmt.Printf(" (%d bytes)", size)
	}
	fmt.Println()
}

func formatResult(status int, url string, size int64) string {
	switch {
	case status == 200:
		if size > 0 {
			return fmt.Sprintf("\033[32m[%d]\033[0m %s (%d bytes)", status, url, size)
		}
		return fmt.Sprintf("\033[32m[%d]\033[0m %s", status, url)
	case status == 301 || status == 302 || status == 303:
		if size > 0 {
			return fmt.Sprintf("\033[33m[%d]\033[0m %s (%d bytes)", status, url, size)
		}
		return fmt.Sprintf("\033[33m[%d]\033[0m %s", status, url)
	case status == 401 || status == 403:
		if size > 0 {
			return fmt.Sprintf("\033[31m[%d]\033[0m %s (%d bytes)", status, url, size)
		}
		return fmt.Sprintf("\033[31m[%d]\033[0m %s", status, url)
	default:
		return ""
	}
}

func saveResults(rawURL string, hits []string) error {
	host := strings.NewReplacer(
		"https://", "",
		"http://", "",
		"/", "_",
		":", "-",
	).Replace(rawURL)
	host = strings.TrimRight(host, "_")
	filename := host + "_scan.txt"

	out, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer out.Close()

	for _, url := range hits {
		fmt.Fprintln(out, url)
	}

	fmt.Printf("\n Results saved to %s\n", filename)
	return nil
}
