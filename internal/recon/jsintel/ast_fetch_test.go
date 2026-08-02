package jsintel

import (
	"cwrap/internal/recon/knowledge"
	"testing"
)

func TestExtractFetchAST_StringLiteral(t *testing.T) {
	source := `
		fetch("/api/users");
	`

	got := mustExtractEndpointsAST(t, source)

	assertEndpoint(t, got, JSEndpoint{
		Path:   "/api/users",
		Method: "GET",
		Kind:   "fetch-ast",
	})
}

func TestExtractFetchAST_ConstantIdentifier(t *testing.T) {
	source := `
		const endpoint = "/api/users";
		fetch(endpoint);
	`

	got := mustExtractEndpointsAST(t, source)

	assertEndpoint(t, got, JSEndpoint{
		Path:   "/api/users",
		Method: "GET",
		Kind:   "fetch-ast",
	})
}

func TestExtractFetchAST_Concatenation(t *testing.T) {
	source := `
		const base = "/api";
		const endpoint = base + "/users";

		fetch(endpoint);
	`

	got := mustExtractEndpointsAST(t, source)

	assertEndpoint(t, got, JSEndpoint{
		Path:   "/api/users",
		Method: "GET",
		Kind:   "fetch-ast",
	})
}

func TestExtractFetchAST_TemplateLiteral(t *testing.T) {
	source := "\n" +
		`const version = "v2";` + "\n" +
		"fetch(`/api/${version}/users`);\n"

	got := mustExtractEndpointsAST(t, source)

	assertEndpoint(t, got, JSEndpoint{
		Path:   "/api/v2/users",
		Method: "GET",
		Kind:   "fetch-ast",
	})
}

func TestExtractFetchAST_Method(t *testing.T) {
	source := `
		const endpoint = "/api/users";

		fetch(endpoint, {
			method: "POST",
			body: JSON.stringify({ name: "test" })
		});
	`

	got := mustExtractEndpointsAST(t, source)

	assertEndpoint(t, got, JSEndpoint{
		Path:   "/api/users",
		Method: "POST",
		Kind:   "fetch-ast",
	})
}

func TestExtractFetchAST_UnresolvedExpressionIgnored(t *testing.T) {
	source := `
		fetch(getEndpoint(currentUser));
	`

	got := mustExtractEndpointsAST(t, source)

	if len(got) != 0 {
		t.Fatalf("expected unresolved endpoint to be ignored, got %#v", got)
	}
}

func TestExtractFetchAST_Deduplicates(t *testing.T) {
	source := `
		const endpoint = "/api/users";

		fetch(endpoint);
		fetch(endpoint);
	`

	got := mustExtractEndpointsAST(t, source)

	if len(got) != 1 {
		t.Fatalf("expected one endpoint, got %#v", got)
	}
}

func assertEndpoint(
	t *testing.T,
	endpoints []JSEndpoint,
	want JSEndpoint,
) {
	t.Helper()

	for _, endpoint := range endpoints {
		if endpoint == want {
			return
		}
	}

	t.Fatalf(
		"endpoint not found\nwant: %#v\ngot:  %#v",
		want,
		endpoints,
	)
}

func TestExtractEndpointsAST_AxiosConstant(t *testing.T) {
	source := `
		const base = "/api";
		const endpoint = base + "/users";

		axios.post(endpoint, {
			name: "test"
		});
	`

	got := mustExtractEndpointsAST(t, source)

	assertEndpoint(t, got, JSEndpoint{
		Path:   "/api/users",
		Method: "POST",
		Kind:   "axios-ast",
	})
}

func TestExtractEndpointsAST_AxiosTemplateLiteral(t *testing.T) {
	source := "\n" +
		`const version = "v2";` + "\n" +
		"axios.get(`/api/${version}/users`);\n"

	got := mustExtractEndpointsAST(t, source)

	assertEndpoint(t, got, JSEndpoint{
		Path:   "/api/v2/users",
		Method: "GET",
		Kind:   "axios-ast",
	})
}

func TestExtractEndpointsAST_XHRConstants(t *testing.T) {
	source := `
		const method = "POST";
		const base = "/api";
		const endpoint = base + "/users";

		const xhr = new XMLHttpRequest();
		xhr.open(method, endpoint);
	`

	got := mustExtractEndpointsAST(t, source)

	assertEndpoint(t, got, JSEndpoint{
		Path:   "/api/users",
		Method: "POST",
		Kind:   "xhr-ast",
	})
}

func TestExtractEndpointsAST_XHRTemplateLiteral(t *testing.T) {
	source := "\n" +
		`const version = "v3";` + "\n" +
		`const xhr = new XMLHttpRequest();` + "\n" +
		"xhr.open(\"GET\", `/api/${version}/items`);\n"

	got := mustExtractEndpointsAST(t, source)

	assertEndpoint(t, got, JSEndpoint{
		Path:   "/api/v3/items",
		Method: "GET",
		Kind:   "xhr-ast",
	})
}

func TestExtractEndpointsAST_AxiosInstance(t *testing.T) {
	source := `
		const api = axios.create({
			baseURL: "https://api.example.com/v1",
		});

		api.get("/users");
	`

	got := mustExtractEndpointsAST(t, source)

	assertEndpoint(t, got, JSEndpoint{
		Path:   "https://api.example.com/v1/users",
		Method: "GET",
		Kind:   "axios-instance-ast",
	})
}

func TestExtractEndpointsAST_AxiosInstanceResolvedBaseURL(t *testing.T) {
	source := `
		const host = "https://api.example.com";
		const version = "/v2";

		const client = axios.create({
			baseURL: host + version,
		});

		client.post("/accounts");
	`

	got := mustExtractEndpointsAST(t, source)

	assertEndpoint(t, got, JSEndpoint{
		Path:   "https://api.example.com/v2/accounts",
		Method: "POST",
		Kind:   "axios-instance-ast",
	})
}

func TestExtractEndpointsAST_AxiosInstanceAbsolutePath(t *testing.T) {
	source := `
		const api = axios.create({
			baseURL: "https://api.example.com/v1",
		});

		api.get("https://other.example.com/status");
	`

	got := mustExtractEndpointsAST(t, source)

	assertEndpoint(t, got, JSEndpoint{
		Path:   "https://other.example.com/status",
		Method: "GET",
		Kind:   "axios-instance-ast",
	})
}

func TestExtractEndpointsAST_ObjectProperties(t *testing.T) {
	source := `
		const config = {
			api: "/api",
			version: "v2",
		};

		fetch(config.api + "/" + config.version + "/users");
	`

	got := mustExtractEndpointsAST(t, source)

	assertEndpoint(t, got, JSEndpoint{
		Path:   "/api/v2/users",
		Method: "GET",
		Kind:   "fetch-ast",
	})
}

func TestExtractEndpointsAST_BracketProperty(t *testing.T) {
	source := `
		const routes = {
			users: "/api/users",
		};

		axios.post(routes["users"]);
	`

	got := mustExtractEndpointsAST(t, source)

	assertEndpoint(t, got, JSEndpoint{
		Path:   "/api/users",
		Method: "POST",
		Kind:   "axios-ast",
	})
}

func TestExtractEndpointsAST_ObjectValueUsesConstant(t *testing.T) {
	source := `
		const base = "/internal";

		const routes = {
			users: base + "/users",
		};

		fetch(routes.users);
	`

	got := mustExtractEndpointsAST(t, source)

	assertEndpoint(t, got, JSEndpoint{
		Path:   "/internal/users",
		Method: "GET",
		Kind:   "fetch-ast",
	})
}

func TestExtractEndpointsAST_AxiosConfig(t *testing.T) {
	source := `
		const base = "/api";

		axios({
			method: "POST",
			url: base + "/users",
			data: {
				name: "test"
			}
		});
	`

	got := mustExtractEndpointsAST(t, source)

	assertEndpoint(t, got, JSEndpoint{
		Path:   "/api/users",
		Method: "POST",
		Kind:   "axios-config-ast",
	})
}

func TestExtractEndpointsAST_AxiosConfigDefaultsToGET(t *testing.T) {
	source := `
		const routes = {
			status: "/api/status",
		};

		axios({
			url: routes.status
		});
	`

	got := mustExtractEndpointsAST(t, source)

	assertEndpoint(t, got, JSEndpoint{
		Path:   "/api/status",
		Method: "GET",
		Kind:   "axios-config-ast",
	})
}

func TestExtractEndpointsAST_AxiosConfigVariableMethod(t *testing.T) {
	source := `
		const method = "PATCH";
		const endpoint = "/api/account";

		axios({
			method: method,
			url: endpoint
		});
	`

	got := mustExtractEndpointsAST(t, source)

	assertEndpoint(t, got, JSEndpoint{
		Path:   "/api/account",
		Method: "PATCH",
		Kind:   "axios-config-ast",
	})
}

func TestLearn_ExtractsResolvedFetchEndpoint(t *testing.T) {
	k := knowledge.New("https://example.com")
	ent := knowledge.NewEntity("https://example.com/app.js")

	body := []byte(`
		const base = "/api";
		const version = "v2";

		fetch(base + "/" + version + "/users", {
			method: "POST"
		});
	`)

	endpoints := Learn(
		k,
		ent,
		"https://example.com/app.js",
		body,
	)

	want := JSEndpoint{
		Path:   "/api/v2/users",
		Method: "POST",
		Kind:   "fetch-ast",
	}

	for _, endpoint := range endpoints {
		if endpoint == want {
			return
		}
	}

	t.Fatalf(
		"resolved fetch endpoint not found\nwant: %#v\ngot:  %#v",
		want,
		endpoints,
	)
}

func mustExtractEndpointsAST(
	t *testing.T,
	source string,
) []JSEndpoint {
	t.Helper()

	endpoints, err := extractEndpointsAST(source)
	if err != nil {
		t.Fatalf("extract AST endpoints: %v", err)
	}

	return endpoints
}
