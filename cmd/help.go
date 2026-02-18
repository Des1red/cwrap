package cmd

import (
	"fmt"

	"github.com/Des1red/clihelp"
)

func printHelp() {

	fmt.Println("cwrap — smart curl wrapper")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  cwrap <method> <url> [options]")
	fmt.Println()
	fmt.Println("Methods:")
	fmt.Println("  get, post, put, delete")
	fmt.Println()
	fmt.Println("Options:")
	clihelp.Print(
		clihelp.F("--run", "bool", "execute request after confirmation"),
		clihelp.F("--as", "string", "request profile (firefox, chrome, api, curl)"),
		clihelp.F("-h", "header", "add header \"Key: Value\""),
		clihelp.F("-c", "cookie", "add cookie \"name=value\""),
		clihelp.F("-b", "string", "bearer token"),
		clihelp.F("-d", "string", "raw request body"),
		clihelp.F("-j", "string", "json body (auto content-type)"),
		clihelp.F("-f", "field", "multipart form field key=value or key=@file"),
		clihelp.F("--filename", "string", "override uploaded filename"),
		clihelp.F("--as-image", "string", "treat next file as image (jpeg,png,gif)"),
		clihelp.F("--follow", "bool", "follow redirects"),
		clihelp.F("--head", "bool", "send HEAD request"),
		clihelp.F("--proxy", "string", "proxy url (http://, socks5://, socks5h://)"),
		clihelp.F("-q", "key=value", "add query parameter"),
	)
	fmt.Println("\nExamples:")
	fmt.Println()
	fmt.Println("Basic requests:")
	clihelp.Print(
		clihelp.F("cwrap get https://example.com", "", "simple GET request"),
		clihelp.F("cwrap get https://api.site/users --as api", "", "API profile"),
		clihelp.F("cwrap get https://site.com -h \"X-API-Key: 123\"", "", "custom header"),
	)

	fmt.Println("\nAuthentication:")
	clihelp.Print(
		clihelp.F("cwrap get https://api.site/me -b TOKEN", "", "bearer authentication"),
		clihelp.F("cwrap get https://site.com -c \"PHPSESSID=abc123\"", "", "cookie session"),
	)

	fmt.Println("\nJSON requests:")
	clihelp.Print(
		clihelp.F("cwrap post https://api.site/login -j '{\"user\":\"admin\",\"pass\":\"123\"}'", "", "JSON body request"),
	)

	fmt.Println("\nMultipart forms:")
	clihelp.Print(
		clihelp.F("cwrap post https://site/upload -f \"user=admin\"", "", "form field"),
		clihelp.F("cwrap post https://site/upload -f \"file=@shell.php\"", "", "file upload"),
	)

	fmt.Println("\nUpload bypass helpers:")
	clihelp.Print(
		clihelp.F("cwrap post /upload -f \"file=@shell.php\" --filename image.jpg", "", "spoof filename"),
		clihelp.F("cwrap post /upload -f \"file=@shell.php\" --as-image jpeg", "", "image mime bypass"),
	)

	fmt.Println("\nExecution:")
	clihelp.Print(
		clihelp.F("cwrap get https://example.com --run", "", "execute immediately"),
	)
	fmt.Println()
}
