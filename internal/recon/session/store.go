package session

import (
	"cwrap/internal/model"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func pathFor(raw string) (string, string) {
	u, _ := url.Parse(raw)
	host := u.Hostname()

	base := filepath.Join(model.ConfigDir(), "sessions")

	return filepath.Join(base, host+".json"), host
}

func Load(raw string) (*Store, error) {
	p, host := pathFor(raw)
	b, err := os.ReadFile(p)
	if err != nil {
		return &Store{
			Host:       host,
			Identities: make(map[string]*IdentitySession),
		}, nil
	}
	var s Store
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if s.Identities == nil {
		s.Identities = make(map[string]*IdentitySession)
	}
	// remove expired JWT cookies before returning
	for _, ident := range s.Identities {
		if ident == nil {
			continue
		}
		for name, c := range ident.Cookies {
			if c != nil && isExpiredJWT(c.Value) {
				delete(ident.Cookies, name)
			}
		}
	}
	return &s, nil
}

func isExpiredJWT(val string) bool {
	parts := strings.Split(val, ".")
	if len(parts) != 3 {
		return false
	}
	payload := parts[1]
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	b, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return false
	}
	var claims map[string]any
	if json.Unmarshal(b, &claims) != nil {
		return false
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return false
	}
	return time.Now().Unix() > int64(exp)
}

func Save(raw string, s *Store) error {
	p, _ := pathFor(raw)

	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(p, b, 0644)
}
