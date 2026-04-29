// internal/bootstrap/bootstrap.go
package bootstrap

import (
	"os"
)

func Init() {
	if ok := checkIfInstalled(); ok {
		return
	}
	install()
}

func checkIfInstalled() bool {
	_, err := os.Stat(configPath())
	return err == nil
}
