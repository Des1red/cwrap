package cmd

import (
	"cwrap/internal/builder"
	"cwrap/internal/flags"
	"cwrap/internal/logger"
	"cwrap/internal/method"
	"fmt"
	"os"
)

func Execute() {

	if len(os.Args) < 3 {
		fmt.Println("usage: cwrap <method> <url>")
		os.Exit(1)
	}

	req := method.Parse(os.Args)

	// parse flags after method + url
	req.Flags = flags.Parse(os.Args[3:])
	result := builder.Build(req)
	logger.PrintCommand(req, result)
}
