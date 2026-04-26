package scan

import (
	"crypto/sha256"
	"io"
	"net/http"
)

type probeResult struct {
	status int
	size   int64
	hash   [32]byte
}

func probe(client *http.Client, url string) (probeResult, error) {
	resp, err := client.Get(url)
	if err != nil {
		return probeResult{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return probeResult{}, err
	}

	return probeResult{
		status: resp.StatusCode,
		size:   int64(len(body)),
		hash:   sha256.Sum256(body),
	}, nil
}
