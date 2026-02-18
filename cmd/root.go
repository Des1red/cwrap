package cmd

import (
	"cwrap/internal/builder"
	"cwrap/internal/flags"
	"cwrap/internal/logger"
	"cwrap/internal/method"
	"cwrap/internal/runner"
	"fmt"
	"os"
)

func Execute() {

	if len(os.Args) == 1 ||
		os.Args[1] == "help" ||
		os.Args[1] == "-h" ||
		os.Args[1] == "--help" {
		printHelp()
		return
	}

	req := method.Parse(os.Args)

	// parse flags after method + url
	req.Flags = flags.Parse(os.Args[3:])
	result := builder.Build(req)
	logger.PrintCommand(req, result)
	if err := runner.ConfirmAndRun(result.Args, req.Flags.Run); err != nil {
		fmt.Println("execution error:", err)
	}
}
