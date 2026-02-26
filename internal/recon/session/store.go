package session

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
)

type Store struct {
	Cookies []Cookie `json:"cookies"`
}

type Cookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func pathFor(raw string) string {
	u, _ := url.Parse(raw)
	host := u.Host
	dir, _ := os.UserConfigDir()
	base := filepath.Join(dir, "cwrap", "sessions")
	os.MkdirAll(base, 0755)
	return filepath.Join(base, host+".json")
}

func Load(raw string) (*Store, error) {
	p := pathFor(raw)

	b, err := os.ReadFile(p)
	if err != nil {
		return &Store{}, nil
	}

	var s Store
	json.Unmarshal(b, &s)
	return &s, nil
}

func Save(raw string, s *Store) error {
	p := pathFor(raw)

	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(p, b, 0644)
}
