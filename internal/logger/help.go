package logger

import (
	"cwrap/internal/model"
	"fmt"

	"github.com/Des1red/clihelp"
)

func PrintHelp() {
	fmt.Println("cwrap — intelligent HTTP client with active security analysis")
	fmt.Println("version " + model.Version)
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  cwrap <command> <url|report> [words] [flags]")
	fmt.Println()

	fmt.Println("How to read commands:")
	clihelp.Print(
		clihelp.F("bare words", "firefox json csrf", "semantic shortcuts understood by cwrap"),
		clihelp.F("key=value", "name=admin page=2", "request data: query params for fetch, body fields for send/upload"),
		clihelp.F("flags", "--as firefox --proxy URL", "explicit options handled by the flag parser"),
		clihelp.F("cookie:name=value,name2=value2", "", "cookie shortcut"),
		clihelp.F("bearer=TOKEN", "", "Authorization: Bearer shortcut"),
	)

	fmt.Println("\nImportant rule:")
	clihelp.Print(
		clihelp.F("fetch key=value", "", "becomes query parameter"),
		clihelp.F("send key=value", "", "becomes request body field"),
		clihelp.F("upload key=value", "", "becomes multipart form field"),
		clihelp.F("profile=firefox", "", "is data, not a profile switch"),
		clihelp.F("firefox / --as firefox", "", "sets the request profile"),
	)

	fmt.Println("\nCommands:")
	clihelp.Print(
		clihelp.F("fetch", "<url>", "retrieve a resource using GET"),
		clihelp.F("send", "<url>", "submit body data using POST"),
		clihelp.F("upload", "<url>", "upload files using multipart POST"),
		clihelp.F("recon", "<url>", "active security reconnaissance"),
		clihelp.F("scan", "<url>", "multi-stage directory and subdomain scanner"),
		clihelp.F("exploit", "<report>", "confirm vulnerabilities and expand access chains"),
	)

	fmt.Println("\nCommand data rules:")
	clihelp.Print(
		clihelp.F("fetch page=2 q=test", "", "adds ?page=2&q=test"),
		clihelp.F("send name=admin pass=123", "", "sends form body: name=admin&pass=123"),
		clihelp.F("send json name=admin age=42", "", "sends JSON body: {\"name\":\"admin\",\"age\":42}"),
		clihelp.F("upload file=@shell.php desc=test", "", "sends multipart fields"),
	)

	fmt.Println("\nProfiles:")
	clihelp.Print(
		clihelp.F("firefox", "", "Firefox-like browser headers"),
		clihelp.F("browser", "", "alias for firefox"),
		clihelp.F("chrome", "", "Chrome-like browser headers"),
		clihelp.F("api", "", "JSON API headers"),
		clihelp.F("curl", "", "minimal curl-like headers"),
		clihelp.F("--as <profile>", "", "explicit profile flag"),
	)

	fmt.Println("\nSend body modes:")
	clihelp.Print(
		clihelp.F("form", "default", "form-urlencoded body"),
		clihelp.F("json", "", "JSON body with type inference"),
		clihelp.F("--as-form", "", "explicit form body mode"),
		clihelp.F("--as-json", "", "explicit JSON body mode"),
		clihelp.F("--as-xml", "", "XML content profile for raw bodies"),
	)

	fmt.Println("\nJSON helpers:")
	clihelp.Print(
		clihelp.F("key=value", "", "normal JSON field"),
		clihelp.F("key.sub=value", "", "nested JSON object"),
		clihelp.F("tag=a tag=b", "", "repeated key becomes JSON array"),
		clihelp.F("age=42 active=true nullv=null", "", "basic type inference"),
	)

	fmt.Println("\nUpload rules:")
	clihelp.Print(
		clihelp.F("file=@path", "", "file upload field"),
		clihelp.F("name=value", "", "normal multipart field"),
		clihelp.F("--filename name.ext", "", "override next uploaded file name"),
		clihelp.F("--as-image png", "", "treat next uploaded file as image/png"),
		clihelp.F("json/form/xml", "", "not allowed with upload"),
	)

	fmt.Println("\nAuthentication:")
	clihelp.Print(
		clihelp.F("bearer=TOKEN", "", "sets Authorization: Bearer TOKEN"),
		clihelp.F("auth=TOKEN", "", "alias for bearer token"),
		clihelp.F("token=TOKEN", "", "alias for bearer token"),
		clihelp.F("cookie:name=value", "", "adds one cookie"),
		clihelp.F("auto-cookie", "", "capture and reuse cookies automatically"),
		clihelp.F("csrf", "", "include CSRF token from saved cookies"),
	)

	fmt.Println("\nRedirect behavior:")
	clihelp.Print(
		clihelp.F("default", "", "requests follow redirects"),
		clihelp.F("nofollow", "fetch shortcut", "do not follow redirects"),
		clihelp.F("--no-follow", "flag", "do not follow redirects"),
	)

	fmt.Println("\nFetch examples:")
	clihelp.Print(
		clihelp.F("cwrap fetch https://site.com", "", "simple GET"),
		clihelp.F("cwrap fetch https://site.com firefox", "", "GET with Firefox headers"),
		clihelp.F("cwrap fetch https://api.site/users api page=2", "", "API GET with query parameter"),
		clihelp.F("cwrap fetch https://site.com cookie:session=abc", "", "GET with cookie"),
		clihelp.F("cwrap fetch https://site.com bearer=TOKEN", "", "GET with bearer token"),
		clihelp.F("cwrap fetch https://site.com nofollow", "", "do not follow redirects"),
	)

	fmt.Println("\nSend examples:")
	clihelp.Print(
		clihelp.F("cwrap send https://api.site/login user=admin pass=123", "", "form POST"),
		clihelp.F("cwrap send https://api.site/login json user=admin pass=123", "", "JSON POST"),
		clihelp.F("cwrap send https://api.site firefox json profile=firefox", "", "Firefox headers; JSON field named profile"),
		clihelp.F("cwrap send https://api.site json user.name=esh user.age=30", "", "nested JSON"),
		clihelp.F("cwrap send https://api.site json tag=a tag=b tag=c", "", "JSON array"),
	)

	fmt.Println("\nUpload examples:")
	clihelp.Print(
		clihelp.F("cwrap upload https://site/upload file=@avatar.png", "", "file upload"),
		clihelp.F("cwrap upload https://site/post title=hello file=@img.jpg", "", "file + multipart fields"),
		clihelp.F("cwrap upload https://site/upload file=@a.png --filename avatar.png", "", "override uploaded filename"),
		clihelp.F("cwrap upload https://site/upload file=@a.png --as-image png", "", "add image/png metadata"),
	)

	fmt.Println("\nScan:")
	clihelp.Print(
		clihelp.F("--dir <path>", "", "directory wordlist; falls back to bundled default"),
		clihelp.F("--domain <path>", "", "subdomain wordlist; enables subdomain stage"),
	)

	fmt.Println("\nScan stages:")
	clihelp.Print(
		clihelp.F("Stage 1", "Directory Discovery", "baseline fingerprinting + parallel wordlist scan"),
		clihelp.F("Stage 2", "Subdirectory Expansion", "re-scan discovered directories"),
		clihelp.F("Stage 3", "Subdomain Enumeration", "wildcard detection + subdomain wordlist scan"),
	)

	fmt.Println("\nScan examples:")
	clihelp.Print(
		clihelp.F("cwrap scan https://site.com --dir wordlist.txt", "", "directory scan"),
		clihelp.F("cwrap scan https://site.com --dir dirs.txt --domain subs.txt", "", "directory + subdomain scan"),
		clihelp.F("cwrap scan https://site.com firefox --dir dirs.txt bearer=TOKEN", "", "authenticated scan with browser headers"),
	)

	fmt.Println("\nRecon modes:")
	clihelp.Print(
		clihelp.F("http", "default", "web app recon: HTML, forms, JS, headers"),
		clihelp.F("web", "alias", "same as http"),
		clihelp.F("api", "", "API recon: JSON, auth behavior, endpoints"),
	)

	fmt.Println("\nRecon flags:")
	clihelp.Print(
		clihelp.F("--tfile <path>", "", "read target URLs from file, one per line"),
	)

	fmt.Println("\nRecon signals:")
	clihelp.Print(
		clihelp.F("AuthBoundary", "", "endpoint allows some identities and denies others"),
		clihelp.F("RoleBoundary", "", "authenticated identity denied by role/permission wall"),
		clihelp.F("ObjectOwnership", "", "different identities access different objects"),
		clihelp.F("CredentiallessTokenIssuance", "", "server issues tokens without credentials"),
		clihelp.F("AdminSurface", "", "path contains admin/internal/debug patterns"),
		clihelp.F("PublicAccess", "", "endpoint accessible without credentials"),
		clihelp.F("StateChanging", "", "endpoint accepts POST/PUT/PATCH/DELETE"),
	)

	fmt.Println("\nRecon examples:")
	clihelp.Print(
		clihelp.F("cwrap recon https://site.com http", "", "web app recon"),
		clihelp.F("cwrap recon https://site.com http firefox", "", "web recon with Firefox headers"),
		clihelp.F("cwrap recon https://api.site/users api", "", "API recon"),
		clihelp.F("cwrap recon https://site.com http bearer=TOKEN", "", "authenticated recon"),
		clihelp.F("cwrap recon --tfile urls.txt http", "", "recon from URL list"),
	)

	fmt.Println("\nExploit stages:")
	clihelp.Print(
		clihelp.F("Stage 1", "Vulnerability Confirmation", "replay report findings to confirm impact"),
		clihelp.F("Stage 2", "Chain Expansion", "expand confirmed findings into attack paths"),
	)

	fmt.Println("\nExploit examples:")
	clihelp.Print(
		clihelp.F("cwrap exploit reports/site-com_2026-04-24.report", "", "confirm and expand findings"),
		clihelp.F("cwrap exploit reports/site-com_2026-04-24.report firefox", "", "use browser headers"),
	)

	fmt.Println("\nRaw flags:")
	clihelp.Print(
		clihelp.F("-h \"Name: value\"", "", "manual header"),
		clihelp.F("-c name=value", "", "manual cookie"),
		clihelp.F("-b TOKEN", "", "bearer token"),
		clihelp.F("-q key=value", "", "query parameter"),
		clihelp.F("-d body", "", "raw request body"),
		clihelp.F("-j '{\"raw\":true}'", "", "raw JSON body"),
		clihelp.F("-f name=value", "", "multipart field"),
		clihelp.F("-f file=@path", "", "multipart file"),
		clihelp.F("--proxy URL", "", "proxy URL"),
		clihelp.F("--head", "", "send HEAD request"),
		clihelp.F("--run", "", "skip confirmation prompt"),
		clihelp.F("--debug", "", "show interpreted request"),
	)

	fmt.Println()
}
