package logger

import (
	"cwrap/internal/builder"
	"cwrap/internal/model"
	"fmt"
)

func PrintCommand(req model.Request, result builder.Result) {
	fmt.Println(key("method")+":", val(req.Method))
	fmt.Println(key("url")+":", val(req.URL))
	fmt.Println(key("run")+":", val(fmt.Sprint(req.Flags.Run)))
	fmt.Println(key("profile")+":", val(req.Flags.Profile))

	fmt.Println(key("effective headers") + ":")
	for _, h := range result.Headers {
		fmt.Printf("  %s: %s\n", key(h.Name), val(h.Value))
	}

	fmt.Println(key("cookies") + ":")
	for _, c := range req.Flags.Cookies {
		fmt.Printf("  %s=%s\n", key(c.Name), val(c.Value))
	}

	if req.Flags.Body != "" && len(req.Flags.Form) == 0 {
		fmt.Println(key("body")+":", val(req.Flags.Body))
	}

	fmt.Println("-------------------------------------")
	fmt.Println(key("curl command")+":", val(result.Cmd))
}
