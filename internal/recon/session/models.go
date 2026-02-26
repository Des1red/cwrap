package session

import (
	"time"
)

type Store struct {
	Host       string                      `json:"host"`
	Identities map[string]*IdentitySession `json:"identities"`
}

type Cookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type IdentitySession struct {
	Updated time.Time               `json:"updated"`
	Cookies map[string]*CookieEntry `json:"cookies"`
}

type CookieEntry struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Source    string `json:"source"` // server/manual
	Path      string `json:"path,omitempty"`
	Domain    string `json:"domain,omitempty"`
	Secure    bool   `json:"secure"`
	HttpOnly  bool   `json:"http_only"`
	Rejected  bool   `json:"rejected"`
	Effective bool   `json:"effective"`
}
