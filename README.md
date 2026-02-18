# cwrap

Human-friendly HTTP client.

cwrap lets you talk to websites and APIs using intent instead of curl syntax.

Instead of remembering headers, encodings and flags — you describe what you want:



Basic Usage
```bash
cwrap <command> <url> [words] [flags]
```

### Example:
```bash
cwrap fetch https://site.com page=2
cwrap send https://api.site/login json user=admin pass=123
```
## Philosophy

curl exposes HTTP mechanics.  
cwrap expresses HTTP meaning.

| You think | curl requires | cwrap |
|--------|--------|--------|
| read page | GET | `fetch` |
| send data | POST + headers | `send` |
| JSON | content-type header | `json` |
| auth | Authorization header | `bearer=` |
| cookies | cookie jar flags | `cookie:` |

The goal is predictable, readable commands.

## Installation
```bash
git clone https://github.com/Des1red/cwrap
cd cwrap
go build
```

Run:
```bash 
./cwrap
```

---

## Commands

### Fetch — read resources

cwrap fetch <url> [words]


Never sends a body.
```bash
cwrap fetch https://httpbin.org/get
cwrap fetch https://api.site/users page=2
cwrap fetch https://site.com browser
cwrap fetch https://api.site/me bearer=TOKEN
```

---

### Send — submit data

cwrap send <url> [words]


Always sends a POST request.
```bash
cwrap send https://httpbin.org/post name=thanos
cwrap send https://httpbin.org/post json name=thanos age=30
cwrap send https://api.site json user.name=thanos user.age=30
```

---

## Semantic Words

- Order does not matter.

### Encoding
- json → application/json
- form → application/x-www-form-urlencoded


### Profiles
- browser → Firefox headers (defualt)
- chrome → Chrome headers
- api → JSON API headers
- curl → Curl headers


### Data
-  key=value


Meaning depends on command:

| Command | Result |
|------|------|
| fetch | query string |
| send  | request body |

---

## JSON Builder

### Automatically infers types:
```bash 
send api json active=true count=5 price=3.14 name=your_name nullval=null
```

```json
{
  "active": true,
  "count": 5,
  "price": 3.14,
  "name": "thanos",
  "nullval": null
}
```
#### Nested objects
```bash
send api json user.name=thanos user.age=30
```
```json
{
  "user": {
    "name": "thanos",
    "age": 30
  }
}
```

#### Arrays
```bash
send api json tag=a tag=b tag=c
```
```json
{
  "tag": ["a","b","c"]
}
```

### Authentication & Cookies
bearer=TOKEN
cookie:name=value
####  Examples:
```bash
cwrap fetch https://api.site/me bearer=abc123
cwrap fetch https://site.com cookie:session=xyz
```

Escape Hatch (curl compatible)
#### Raw flags still work:
```bash
-h "Header: value"
-d '{"raw":true}'
-f file=@image.png
--proxy http://127.0.0.1:8080
--run
```

cwrap interprets words first, flags second.

### Examples
#### Read paginated API
```bash
cwrap fetch https://api.site/users api page=2 limit=20
```
#### Login request
```bash
cwrap send https://api.site/login json username=admin password=123
```

#### Authenticated request
```bash
cwrap fetch https://api.site/me bearer=TOKEN
```

#### Complex JSON
```bash
cwrap send https://api.site json filter.name=thanos filter.age=30 tag=a tag=b
```

## Why not curl?
curl describes how
cwrap describes what
```bash
curl -X POST -H "Content-Type: application/json" -d '{"user":"admin"}'
```
### vs
```bash
cwrap send site json user=admin
```
License
MIT


---
