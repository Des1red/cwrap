package bootstrap

import (
	"cwrap/internal/model"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func Uninstall() {
	if ok := startUninstall(); ok {
		fmt.Println("cwrap uninstalled.")
		os.Exit(0)
	}
	fmt.Println("cwrap uninstall incomplete.")
	os.Exit(1)
}
func startUninstall() bool {
	ok1 := removeBinary()
	ok2 := removeConfig()
	return ok1 && ok2
}

func removeBinary() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Println("Failed to resolve home dir:", err)
		return false
	}
	dest := filepath.Join(home, ".local", "bin", "cwrap")

	if err := os.Remove(dest); err != nil {
		if os.IsNotExist(err) {
			log.Println("Binary not found at", dest, "(already removed)")
			return true
		}
		log.Println("Failed to remove binary:", err)
		return false
	}
	log.Println("Removed binary:", dest)
	return true
}

func removeConfig() bool {
	dir := model.ConfigDir()
	if err := os.RemoveAll(dir); err != nil {
		log.Println("Failed to remove config dir:", err)
		return false
	}
	log.Println("Removed config dir:", dir)
	return true
}
