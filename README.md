# cwrap

cwrap is a smart wrapper around curl that removes the need to remember complex flags while still generating real, copy-pasteable curl commands.

It builds the request, shows you exactly what will be sent, and optionally executes it.

Basic Usage
```bash
cwrap <method> <url> [options]
```

### Example:
```bash
cwrap get https://example.com
cwrap post https://api.site/login -j '{"user":"admin","pass":"123"}'
cwrap get https://site.com -b TOKEN --run
```
### Features

- Human-friendly flags → real curl commands

- Browser impersonation (--as firefox, --as chrome)

- JSON body support (-j)

- Multipart forms & file uploads (-f)

- Automatic MIME detection

- Upload bypass helpers (--filename, --as-image)

- Safe execution preview before sending

- Copy-pasteable shell-safe output

Examples
#### API request
```bash
cwrap get https://api.site/users --as api
```
#### Auth
```bash
cwrap get https://api.site/me -b TOKEN
```
#### Upload file
```bash
cwrap post https://site/upload -f "file=@shell.php"
```
#### Upload bypass
```bash
cwrap post /upload -f "file=@shell.php" --as-image jpeg
```
#### Execute immediately
```bash
cwrap get https://httpbin.org/get --run
```

### Philosophy

cwrap is not a curl replacement.
It is a productivity tool — you describe the request, cwrap builds the correct curl.