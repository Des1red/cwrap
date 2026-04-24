package intent

import (
	"cwrap/internal/logger"
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
	case "recon":
		return &ReconHandler{}
	case "exploit":
		return &ExploitHandler{}
	case "scan":
		return &ScanHandler{}
	default:
		return nil
	}
}

func Parse(args []string) model.Request {
	if len(args) < 2 {
		logger.PrintHelp()
		os.Exit(1)
	}

	cmd := strings.ToLower(args[1])

	var url string
	var path string

	// If a third argument exists AND it is not a flag,
	// treat it as URL
	if len(args) >= 3 && !strings.HasPrefix(args[2], "-") {
		switch strings.ToLower(args[1]) {
		case "exploit":
			path = args[2]
		case "scan":
			url = args[2]
			if len(args) >= 4 && !strings.HasPrefix(args[3], "-") {
				path = args[3]
			}
		default:
			url = args[2]
		}
	}
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
	case "recon":
		return model.Request{
			Method:   "GET",
			URL:      url,
			Original: "recon"}
	case "exploit":
		return model.Request{
			FilePath: path, // report path, not a URL
			Original: "exploit",
		}
	case "scan":
		return model.Request{
			Method:   "GET",
			URL:      url,
			FilePath: path,
			Original: "scan",
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
