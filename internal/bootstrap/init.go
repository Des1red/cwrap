// internal/bootstrap/bootstrap.go
package bootstrap

import (
	"fmt"
	"os"
)

// bootstrap.go
func Init(force bool) {
	if ok := checkIfInstalled(); ok {
		if !force {
			return
		}
		fmt.Println("cwrap already installed, reinstalling.")
	} else {
		fmt.Println("First time run detected. Initializing first boot.")
	}
	install()
}

func checkIfInstalled() bool {
	_, err := os.Stat(configPath())
	return err == nil
}
