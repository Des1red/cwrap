package behavior

import (
	"crypto/sha256"
	"fmt"
)

func fpString(status int, body []byte) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf("%d:%x", status, sum)
}
