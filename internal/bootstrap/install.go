package bootstrap

import (
	"cwrap/internal/model"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"

	instll "github.com/Des1red/goinstall/cmd"
)

func install() {
	ok1 := createconfig()
	ok2 := createbinary()

	if ok1 && ok2 {
		log.Println("cwrap successfully installed!")
		os.Exit(0)
	}

	log.Println("cwrap installation incomplete.")
	os.Exit(1)
}

func createconfig() bool {
	dir :=
		filepath.Dir(
			configPath(),
		)

	if err :=
		os.MkdirAll(
			dir,
			0755,
		); err != nil {

		log.Println(
			"Failed to create config directory:",
			err,
		)

		return false
	}

	cfg :=
		Config{
			Version:     model.Version,
			InstalledAt: time.Now(),
			UpdatedAt:   time.Now(),
		}

	b,
		err :=
		json.MarshalIndent(
			cfg,
			"",
			"  ",
		)

	if err != nil {
		log.Println(
			"Failed to marshal config:",
			err,
		)

		return false
	}

	if err :=
		os.WriteFile(
			configPath(),
			b,
			0644,
		); err != nil {

		log.Println(
			"Failed to write config:",
			err,
		)

		return false
	}

	return true
}

func createbinary() bool {
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
		instll.Install(
			true,
			true,
		)

	if err != nil {
		log.Println(
			"Failed to install binary:",
			err,
		)

		return false
	}

	return true
}
