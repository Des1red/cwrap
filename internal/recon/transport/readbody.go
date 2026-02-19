package transport

import (
	"io"
	"net/http"
)

func ReadBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
