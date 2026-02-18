package method

import (
	"cwrap/internal/model"
	"fmt"
	"os"
	"strings"
)

func Parse(args []string) model.Request {
	method := strings.ToUpper(args[1])
	url := args[2]

	switch method {
	case "GET", "POST", "PUT", "DELETE", "DOWNLOAD":
	default:
		fmt.Println("unknown method:", method)
		os.Exit(1)
	}

	return model.Request{
		Method: method,
		URL:    url,
	}
}
