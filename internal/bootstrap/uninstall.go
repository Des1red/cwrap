package bootstrap

import (
	"cwrap/internal/model"
	"fmt"
	"log"
	"os"

	instll "github.com/Des1red/goinstall/cmd"
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
	err :=
		instll.SetBinaryName(
			"cwrap",
		)

	if err != nil {
		log.Println(
			"Failed to set binary name:",
			err,
		)

		return false
	}

	err =
		instll.Uninstall(
			true,
			true,
		)

	if err != nil {
		log.Println(
			"Failed to remove binary:",
			err,
		)

		return false
	}

	return true
}

func removeConfig() bool {
	dir :=
		model.ConfigDir()

	if err :=
		os.RemoveAll(
			dir,
		); err != nil {

		log.Println(
			"Failed to remove config dir:",
			err,
		)

		return false
	}

	log.Println(
		"Removed config dir:",
		dir,
	)

	return true
}
