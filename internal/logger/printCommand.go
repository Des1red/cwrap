package logger

import (
	"cwrap/internal/builder"
	"cwrap/internal/model"
	"fmt"
)

func PrintCommand(req model.Request, result builder.Result) {
	fmt.Println("method:", req.Method)
	fmt.Println("url:", req.URL)
	fmt.Println("run:", req.Flags.Run)
	fmt.Println("profile:", req.Flags.Profile)

	fmt.Println("effective headers:")
	for _, h := range result.Headers {
		fmt.Printf("  %s: %s\n", h.Name, h.Value)
	}

	fmt.Println("cookies:")
	for _, c := range req.Flags.Cookies {
		fmt.Printf("  %s=%s\n", c.Name, c.Value)
	}

	if req.Flags.Body != "" && len(req.Flags.Form) == 0 {
		fmt.Println("body:", req.Flags.Body)
	}

	fmt.Println("-------------------------------------")
	fmt.Println("curl command:", result.Cmd)
}
