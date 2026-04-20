package behavior

import (
	"cwrap/internal/recon/knowledge"
	"net/http"
)

type LearnFunc func(url string, resp *http.Response, body []byte)

// Engine executes active probing and reasoning.
type Engine struct {
	k   *knowledge.Knowledge
	int Interpreter

	identities []Identity

	baseStatus int
	baseBody   []byte
	baseFP     fingerprint

	authBoundaryConfirmed bool
	authConfidence        int

	sessionCookies       map[string]string // live session cookies, updated as probing proceeds
	discoveredIdentities map[string]bool   // tracks role|uid combos already added as live identities
	knownRoleUIDs        map[string]bool   // role|uid of all real identities seen so far

	debug bool
}

func New(k *knowledge.Knowledge, i Interpreter, debug bool) *Engine {
	return &Engine{
		k:   k,
		int: i,

		debug:                debug,
		sessionCookies:       make(map[string]string),
		discoveredIdentities: make(map[string]bool),
		knownRoleUIDs:        make(map[string]bool),
	}
}
