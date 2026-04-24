package logger

import (
	"fmt"

	"github.com/Des1red/clihelp"
)

func PrintHelp() {
	fmt.Println("cwrap — intelligent HTTP client with active security analysis")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  cwrap <command> <url> [words] [flags]")
	fmt.Println()
	fmt.Println("Commands:")
	clihelp.Print(
		clihelp.F("fetch", "<url>", "retrieve a resource (GET)"),
		clihelp.F("send", "<url>", "submit data (POST)"),
		clihelp.F("upload", "<url>", "upload files (multipart POST)"),
		clihelp.F("recon", "<url>", "active security reconnaissance"),
		clihelp.F("exploit", "<report>", "confirm vulnerabilities and expand access chains"),
		clihelp.F("scan", "<url> <wordlist>", "parallel subdirectory scanner"),
	)

	fmt.Println("\nRecon profiles:")
	clihelp.Print(
		clihelp.F("http", "default", "web app recon — HTML, forms, JS, headers"),
		clihelp.F("api", "", "API recon — JSON structure, auth, endpoints"),
	)

	fmt.Println("\nRecon flags:")
	clihelp.Print(
		clihelp.F("--tfile", "<path>", "read target URLs from file (one per line)"),
	)

	fmt.Println("\nRecon signals:")
	clihelp.Print(
		clihelp.F("AuthBoundary", "", "endpoint allows some identities and denies others"),
		clihelp.F("RoleBoundary", "", "authenticated identity denied — role/permission wall"),
		clihelp.F("ObjectOwnership", "", "different identities access different objects"),
		clihelp.F("CredentiallessTokenIssuance", "", "server issues tokens without credentials"),
		clihelp.F("AdminSurface", "", "path contains admin/internal/debug patterns"),
		clihelp.F("PublicAccess", "", "endpoint accessible without any credentials"),
		clihelp.F("StateChanging", "", "endpoint accepts POST/PUT/PATCH/DELETE"),
	)

	fmt.Println("\nExploit stages:")
	clihelp.Print(
		clihelp.F("Stage 1 — Vulnerability Confirmation", "", "replays vault tokens to prove findings"),
		clihelp.F("Stage 2 — Chain Expansion", "", "expands confirmed findings to measure impact"),
	)

	fmt.Println("\nEncoding words (send/upload):")
	clihelp.Print(
		clihelp.F("json", "", "encode body as JSON"),
		clihelp.F("form", "", "encode body as form-urlencoded"),
	)

	fmt.Println("\nProfile words:")
	clihelp.Print(
		clihelp.F("browser", "default", "Firefox headers"),
		clihelp.F("chrome", "", "Chrome headers"),
		clihelp.F("api", "", "JSON API headers"),
		clihelp.F("curl", "", "minimal curl headers"),
	)

	fmt.Println("\nData words:")
	clihelp.Print(
		clihelp.F("key=value", "", "query param (fetch) or body field (send/upload)"),
		clihelp.F("file=@path", "", "file field (upload only)"),
		clihelp.F("key.sub=value", "", "nested JSON object (send json)"),
		clihelp.F("key=a key=b", "", "JSON array — repeat same key (send json)"),
	)

	fmt.Println("\nAuthentication words:")
	clihelp.Print(
		clihelp.F("bearer=TOKEN", "", "Authorization: Bearer header"),
		clihelp.F("cookie:name=value", "", "add a cookie"),
		clihelp.F("auto-cookie", "", "capture and reuse cookies automatically"),
		clihelp.F("csrf", "", "include csrf header from saved cookies"),
	)

	fmt.Println("\nBehavior words:")
	clihelp.Print(
		clihelp.F("nofollow", "", "do not follow redirects"),
	)

	fmt.Println("\nExamples — fetch:")
	clihelp.Print(
		clihelp.F("cwrap fetch https://site.com", "", "simple GET"),
		clihelp.F("cwrap fetch https://api.site/users api page=2", "", "API with query params"),
		clihelp.F("cwrap fetch https://site.com bearer=TOKEN", "", "authenticated request"),
		clihelp.F("cwrap fetch https://site.com cookie:session=abc", "", "with cookie"),
		clihelp.F("cwrap fetch https://site.com nofollow", "", "inspect redirect"),
	)

	fmt.Println("\nExamples — send:")
	clihelp.Print(
		clihelp.F("cwrap send https://api.site/login user=admin pass=123", "", "form POST"),
		clihelp.F("cwrap send https://api.site/login json user=admin pass=123", "", "JSON POST"),
		clihelp.F("cwrap send https://api.site json user.name=esh user.age=30", "", "nested JSON"),
		clihelp.F("cwrap send https://api.site json tag=a tag=b tag=c", "", "JSON array"),
	)

	fmt.Println("\nExamples — upload:")
	clihelp.Print(
		clihelp.F("cwrap upload https://site/upload file=@avatar.png", "", "file upload"),
		clihelp.F("cwrap upload https://site/post title=hello file=@img.jpg", "", "file + fields"),
	)

	fmt.Println("\nExamples — recon:")
	clihelp.Print(
		clihelp.F("cwrap recon https://site.com http", "", "web app recon"),
		clihelp.F("cwrap recon https://site.com", "", "uses default:web app recon"),
		clihelp.F("cwrap recon https://api.site/users api", "", "API recon"),
		clihelp.F("cwrap recon https://site.com http bearer=TOKEN", "", "authenticated recon"),
		clihelp.F("cwrap recon --tfile urls.txt http", "", "recon from URL list"),
	)

	fmt.Println("\nExamples — exploit:")
	clihelp.Print(
		clihelp.F("cwrap exploit reports/site-com_2026-04-24.report", "", "confirm and expand findings"),
		clihelp.F("cwrap exploit reports/site-com_2026-04-24.report", "", "show chain details"),
	)

	fmt.Println("\nExamples — scan:")
	clihelp.Print(
		clihelp.F("cwrap scan https://site.com wordlist.txt", "", "subdirectory scan"),
		clihelp.F("cwrap scan https://site.com wordlist.txt bearer=TOKEN", "", "authenticated scan"),
		clihelp.F("cwrap recon --tfile site-com_scan.txt", "", "recon discovered paths"),
	)

	fmt.Println("\nEscape hatch (raw flags):")
	clihelp.Print(
		clihelp.F("-h \"Name: value\"", "", "manual header"),
		clihelp.F("-d '{\"raw\":true}'", "", "raw request body"),
		clihelp.F("--proxy http://127.0.0.1:8080", "", "proxy"),
		clihelp.F("--run", "", "skip confirmation prompt"),
	)

	fmt.Println()
}
