package scan

import (
	"net/http"
)

func stageOne(client *http.Client, base, wordlist string, bf baseline) scanResult {
	return scanBase(client, base, wordlist, bf, scanAllPaths)
}
