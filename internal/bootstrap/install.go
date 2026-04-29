package bootstrap

import (
	"cwrap/internal/model"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func install() {
	log.Println("First time run detected. Initializing first boot.")
	ok1 := createconfig()
	ok2 := createbinary()
	if ok1 && ok2 {
		log.Println("cwrap successfully installed!")
		os.Exit(0)
	} else {
		log.Println("cwrap installation incomplete.")
		os.Exit(1)
	}
}

func createconfig() bool {
	dir := filepath.Dir(configPath())
	os.MkdirAll(dir, 0755)

	cfg := Config{
		Version:     model.Version,
		InstalledAt: time.Now(),
		UpdatedAt:   time.Now(),
	}

	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return false
	}

	if err := os.WriteFile(configPath(), b, 0644); err != nil {
		return false
	}
	return true
}

func createbinary() bool {
	// build
	cmd := exec.Command("go", "build", "-ldflags", "-X cwrap/internal/model.Version="+model.Version, "-o", "/tmp/cwrap", ".")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Println("Failed to build binary.")
		return false
	}
	log.Println("Binary successfully built.")

	// install to ~/.local/bin
	home, _ := os.UserHomeDir()
	binDir := filepath.Join(home, ".local", "bin")
	os.MkdirAll(binDir, 0755)
	dest := filepath.Join(binDir, "cwrap")

	// check if binary already exists
	if _, err := os.Stat(dest); err == nil {
		fmt.Printf("cwrap already exists at %s. Replace? (y/n): ", dest)
		var input string
		fmt.Scanln(&input)
		if input != "y" && input != "Y" {
			log.Println("Installation aborted.")
			return false
		} else {
			err := os.Remove(dest)
			if err != nil {
				log.Println("Failed to remove: " + dest)
				return false
			}
		}
	}

	src, _ := os.ReadFile("/tmp/cwrap")
	if err := os.WriteFile(dest, src, 0755); err != nil {
		log.Println("Failed to install binary: ", err)
		return false
	}
	log.Printf("cwrap installed to %s", dest)
	log.Printf("Run 'hash -r' or open a new terminal if cwrap command is not found")
	log.Printf("Make sure %s is in your PATH", binDir)
	return true
}
