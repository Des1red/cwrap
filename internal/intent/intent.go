package intent

import (
	"cwrap/internal/model"
	"fmt"
	"os"
	"strings"
)

type Handler interface {
	Translate(args []string) []string
	ApplyDefaults(req *model.Request, f *model.Flags)
}

func Resolve(req model.Request) Handler {
	switch req.Original {
	case "fetch":
		return FetchHandler{}
	case "send":
		return SendHandler{}
	case "upload":
		return UploadHandler{}
	default:
		return nil
	}
}

func Parse(args []string) model.Request {
	cmd := strings.ToLower(args[1])
	url := args[2]

	switch cmd {
	case "fetch":
		return model.Request{
			Method:   "GET",
			URL:      url,
			Original: "fetch",
		}
	case "send":
		return model.Request{
			Method:   "POST",
			URL:      url,
			Original: "send",
		}
	case "upload":
		return model.Request{
			Method:   "POST",
			URL:      url,
			Original: "upload",
		}

	case "get", "post", "put", "delete", "download":
		return model.Request{
			Method:   strings.ToUpper(cmd),
			URL:      url,
			Original: cmd,
		}
	default:
		fmt.Println("unknown method:", cmd)
		os.Exit(1)
	}
	return model.Request{}
}
