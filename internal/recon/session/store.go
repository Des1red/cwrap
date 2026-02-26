package session

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
)

func pathFor(raw string) (string, string) {
	u, _ := url.Parse(raw)
	host := u.Hostname()

	dir, _ := os.UserConfigDir()
	base := filepath.Join(dir, "cwrap", "sessions")
	os.MkdirAll(base, 0755)

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

	return &s, nil
}

func Save(raw string, s *Store) error {
	p, _ := pathFor(raw)

	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(p, b, 0644)
}
