package scan

import (
	"cwrap/internal/model"
	"fmt"
	"net/http"
	"os"
)

func stageOne(client *http.Client, base, wordlist string, bf baseline) scanResult {
	return scanBase(client, base, wordlist, bf)
}

func validate(req *model.Request) error {
	if req.URL == "" {
		return fmt.Errorf("scan requires a URL — cwrap scan <url> /path/to/words.txt")
	}
	if req.FilePath != "" {
		return nil
	}
	wl := defaultWordlist()
	if wl == "" {
		return fmt.Errorf("scan requires a wordlist — cwrap scan <url> /path/to/words.txt")
	}
	if _, err := os.Stat(wl); err != nil {
		return fmt.Errorf("no wordlist provided and default not found at %s", wl)
	}
	req.FilePath = wl
	return nil
}
