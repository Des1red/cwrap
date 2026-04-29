package cmd

import (
	"cwrap/internal/bootstrap"
	"cwrap/internal/logger"
	"cwrap/internal/model"
	"fmt"
	"os"
)

func boot() {
	bootstrap.Init()
}

func manFlags() {
	if len(os.Args) == 1 ||
		os.Args[1] == "help" ||
		os.Args[1] == "-h" ||
		os.Args[1] == "--help" {
		logger.PrintHelp()
		os.Exit(0)
	}
	if os.Args[1] == "version" || os.Args[1] == "--version" {
		fmt.Println(model.Version)
		os.Exit(0)
	}

}
