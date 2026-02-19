package behavior

import (
	"crypto/sha1"
)

type fingerprint struct {
	Status int
	Hash   [20]byte
}

func makeFingerprint(status int, body []byte) fingerprint {
	return fingerprint{
		Status: status,
		Hash:   sha1.Sum(body),
	}
}
