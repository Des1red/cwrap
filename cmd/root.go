package cmd

import (
	"cwrap/internal/flags"
	"cwrap/internal/intent"
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

	if err := runner.Execute(req); err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}

}
