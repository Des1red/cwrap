package cmd

import (
	"fmt"

	"github.com/Des1red/clihelp"
)

func printHelp() {

	fmt.Println("cwrap — human friendly HTTP client")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  cwrap <command> <url> [words] [flags]")
	fmt.Println()

	fmt.Println("Commands:")
	clihelp.Print(
		clihelp.F("fetch  <url>", "", "retrieve resource (follows redirects)"),
		clihelp.F("send   <url>", "", "submit structured data (POST)"),
		clihelp.F("upload <url>", "", "upload files (multipart POST)"),
	)

	fmt.Println("\nSemantic words (order doesn't matter):")
	clihelp.Print(
		clihelp.F("json", "", "encode body as JSON (send)"),
		clihelp.F("form", "", "encode body as form (send)"),
		clihelp.F("browser", "", "browser profile (firefox headers)"),
		clihelp.F("api", "", "API profile (json headers)"),
		clihelp.F("nofollow", "", "do not follow redirects"),
		clihelp.F("key=value", "", "query (fetch) or body (send/upload field)"),
		clihelp.F("file=@path", "", "file field (upload only)"),
		clihelp.F("cookie:name=value", "", "add cookie"),
		clihelp.F("bearer=TOKEN", "", "authorization bearer token"),
	)

	fmt.Println("\nExamples:")
	fmt.Println()

	fmt.Println("Read data:")
	clihelp.Print(
		clihelp.F("cwrap fetch https://site.com", "", "simple request"),
		clihelp.F("cwrap fetch https://site.com nofollow", "", "inspect redirect response"),
		clihelp.F("cwrap fetch https://api.site/users api", "", "API headers"),
		clihelp.F("cwrap fetch https://site.com page=2 limit=10", "", "query params"),
		clihelp.F("cwrap fetch https://site.com cookie:session=abc", "", "session cookie"),
	)

	fmt.Println("\nSend data:")
	clihelp.Print(
		clihelp.F("cwrap send https://api.site/login user=admin pass=123", "", "form body"),
		clihelp.F("cwrap send https://api.site/login json user=admin pass=123", "", "JSON body"),
		clihelp.F("cwrap send https://api.site json user.name=your_name user.age=30", "", "nested JSON"),
	)

	fmt.Println("\nUpload files:")
	clihelp.Print(
		clihelp.F("cwrap upload https://site/upload file=@avatar.png", "", "simple upload"),
		clihelp.F("cwrap upload https://site/post title=hello file=@a.jpg", "", "file + fields"),
		clihelp.F("cwrap upload https://api.site/import browser file=@dump.zip", "", "browser style upload"),
	)

	fmt.Println("\nAuthentication:")
	clihelp.Print(
		clihelp.F("cwrap fetch https://api.site/me bearer=TOKEN", "", "bearer auth"),
	)

	fmt.Println("\nEscape hatch (raw curl flags still work):")
	clihelp.Print(
		clihelp.F("-h \"Header: value\"", "", "manual header"),
		clihelp.F("-d '{...}'", "", "raw body"),
		clihelp.F("--proxy URL", "", "proxy"),
		clihelp.F("--run", "", "execute without prompt"),
	)

	fmt.Println()
}
