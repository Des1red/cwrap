package scan

import (
	"cwrap/internal/model"
	"fmt"
	"os"
	"path/filepath"
)

func validateDirScan(req *model.Request) error {
	if req.FilePath != "" {
		return nil
	}
	wl := defaultWordlist()
	if wl == "" {
		return fmt.Errorf("no wordlist available")
	}
	if _, err := os.Stat(wl); err != nil {
		return fmt.Errorf("default wordlist not found at %s", wl)
	}
	req.FilePath = wl
	return nil
}

func defaultWordlist() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(exe), "./", "small-directory-list-20k.txt")
}

func validateSubdomainScan(req *model.Request) error {
	if req.SubdomainFile != "" {
		return nil
	}
	wl := defaultSubdomainWordlist()
	if wl == "" {
		return fmt.Errorf("no subdomain wordlist available")
	}
	if _, err := os.Stat(wl); err != nil {
		return fmt.Errorf("default subdomain wordlist not found at %s", wl)
	}
	req.SubdomainFile = wl
	return nil
}

// defaultSubdomainWordlist returns the path to the bundled subdomain wordlist,
// resolved relative to the cwrap executable — same pattern as defaultWordlist().
func defaultSubdomainWordlist() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(exe), "./", "small-subdomain-list-20k.txt")
}
