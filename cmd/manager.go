package cmd

import (
	"cwrap/internal/bootstrap"
	"cwrap/internal/logger"
	"cwrap/internal/model"
	"fmt"
	"os"
)

func boot() {
	bootstrap.Init(false)
}

func uninstall() {
	bootstrap.Uninstall()
}

func manFlags() {
	if len(os.Args) == 1 ||
		os.Args[1] == "help" ||
		os.Args[1] == "-h" ||
		os.Args[1] == "--help" {
		logger.PrintHelp()
		os.Exit(0)
	}
	if len(os.Args) > 1 && os.Args[1] == "--uninstall" {
		uninstall()
	}
	if len(os.Args) > 1 && os.Args[1] == "--install" {
		bootstrap.Init(true)
	}
	if os.Args[1] == "version" || os.Args[1] == "--version" {
		fmt.Println(model.Version)
		os.Exit(0)
	}

}
