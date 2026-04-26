package transport

import (
	"fmt"
	"net/http"
)

func dumpRequest(r *http.Request, debug bool) {
	if !debug {
		return
	}
	fmt.Printf("  → %s %s\n", r.Method, r.URL)
	for k, v := range r.Header {
		fmt.Printf("     %s: %s\n", k, v)
	}
}
