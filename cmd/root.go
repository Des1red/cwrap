package cmd

import (
	"cwrap/internal/builder"
	"cwrap/internal/flags"
	"cwrap/internal/intent"
	"cwrap/internal/logger"
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

	req := intent.Parse(os.Args)
	handler := intent.Resolve(req)

	args := os.Args[3:]
	if handler != nil {
		args = handler.Translate(args)
	}

	// parse flags after method + url
	req.Flags = flags.Parse(args)
	if handler != nil {
		handler.ApplyDefaults(&req, &req.Flags)
	}

	result := builder.Build(req)
	logger.PrintCommand(req, result)
	if err := runner.ConfirmAndRun(result.Args, req.Flags.Run); err != nil {
		fmt.Println("execution error:", err)
	}
}
