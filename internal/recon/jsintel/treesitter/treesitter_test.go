package treesitter

import (
	"strings"
	"testing"
)

func TestParseJavaScriptTreeValidSource(t *testing.T) {
	source := []byte(`
		const endpoint = "/api/users";
		fetch(endpoint);
	`)

	tree, err := parseJavaScriptTree(source)
	if err != nil {
		t.Fatalf("parseJavaScriptTree returned error: %v", err)
	}
	defer tree.Close()

	root := tree.RootNode()

	if root == nil {
		t.Fatal("expected non-null root node")
	}

	if root.Kind() != "program" {
		t.Fatalf("expected root kind program, got %q", root.Kind())
	}

	if root.HasError() {
		t.Fatal("expected valid JavaScript tree without errors")
	}
}

func TestParseJavaScriptTreeMalformedSourceStillReturnsTree(t *testing.T) {
	source := []byte(`
		const endpoint = "/api/users";
		fetch(endpoint);

		function broken( {
	`)

	tree, err := parseJavaScriptTree(source)
	if err != nil {
		t.Fatalf("expected tree despite malformed source, got error: %v", err)
	}
	defer tree.Close()

	root := tree.RootNode()

	if root == nil {
		t.Fatal("expected non-null root node")
	}

	if !root.HasError() {
		t.Fatal("expected malformed source to produce error nodes")
	}
}

func TestParseJavaScriptTreeEmptySource(t *testing.T) {
	tree, err := parseJavaScriptTree(nil)
	if err != nil {
		t.Fatalf("parseJavaScriptTree returned error: %v", err)
	}
	defer tree.Close()

	root := tree.RootNode()

	if root == nil {
		t.Fatal("expected non-null root node")
	}

	if root.Kind() != "program" {
		t.Fatalf("expected root kind program, got %q", root.Kind())
	}
}

func TestFindHTTPCallScopesFetchFunction(t *testing.T) {
	source := []byte(`
		function loadUsers() {
			const base = "/api";
			const endpoint = base + "/users";

			return fetch(endpoint);
		}
	`)

	scopes, err := findHTTPCallScopes(source)
	if err != nil {
		t.Fatalf("findHTTPCallScopes returned error: %v", err)
	}

	if len(scopes) != 1 {
		t.Fatalf("expected 1 scope, got %d", len(scopes))
	}

	if scopes[0].Kind != "function_declaration" {
		t.Fatalf(
			"expected function_declaration, got %q",
			scopes[0].Kind,
		)
	}

	if !strings.Contains(scopes[0].Source, `const base = "/api"`) {
		t.Fatalf(
			"expected complete function scope, got:\n%s",
			scopes[0].Source,
		)
	}

	if !strings.Contains(scopes[0].Source, "fetch(endpoint)") {
		t.Fatalf(
			"expected fetch call in scope, got:\n%s",
			scopes[0].Source,
		)
	}
}

func TestFindHTTPCallScopesAxiosInstance(t *testing.T) {
	source := []byte(`
		const loadUsers = async () => {
			const api = axios.create({
				baseURL: "https://api.example.com"
			});

			return api.get("/users");
		};
	`)

	scopes, err := findHTTPCallScopes(source)
	if err != nil {
		t.Fatalf("findHTTPCallScopes returned error: %v", err)
	}

	if len(scopes) != 1 {
		t.Fatalf("expected 1 scope, got %d", len(scopes))
	}

	if scopes[0].Kind != "arrow_function" {
		t.Fatalf(
			"expected arrow_function, got %q",
			scopes[0].Kind,
		)
	}

	if !strings.Contains(scopes[0].Source, `api.get("/users")`) {
		t.Fatalf(
			"expected Axios call in scope, got:\n%s",
			scopes[0].Source,
		)
	}
}

func TestFindHTTPCallScopesDeduplicatesSameFunction(t *testing.T) {
	source := []byte(`
		function syncUsers() {
			fetch("/api/users");
			axios.post("/api/sync");
		}
	`)

	scopes, err := findHTTPCallScopes(source)
	if err != nil {
		t.Fatalf("findHTTPCallScopes returned error: %v", err)
	}

	if len(scopes) != 1 {
		t.Fatalf(
			"expected one deduplicated function scope, got %d",
			len(scopes),
		)
	}
}

func TestExtractEndpointsFromTreeScopesFetchConstant(t *testing.T) {
	source := []byte(`
		function loadUsers() {
			const base = "/api";
			const endpoint = base + "/users";

			return fetch(endpoint);
		}
	`)

	scopes, err := findHTTPCallScopes(source)
	if err != nil {
		t.Fatalf("findHTTPCallScopes returned error: %v", err)
	}

	endpoints, parsed, failed :=
		extractEndpointsFromTreeScopes(scopes)

	if parsed != 1 {
		t.Fatalf("expected 1 parsed scope, got %d", parsed)
	}

	if failed != 0 {
		t.Fatalf("expected 0 failed scopes, got %d", failed)
	}

	if len(endpoints) != 1 {
		t.Fatalf(
			"expected 1 endpoint, got %d: %#v",
			len(endpoints),
			endpoints,
		)
	}

	endpoint := endpoints[0]

	if endpoint.Method != "GET" {
		t.Fatalf("expected GET, got %q", endpoint.Method)
	}

	if endpoint.Path != "/api/users" {
		t.Fatalf(
			"expected /api/users, got %q",
			endpoint.Path,
		)
	}

	if endpoint.Kind != "fetch-ast" {
		t.Fatalf(
			"expected fetch-ast, got %q",
			endpoint.Kind,
		)
	}
}

func TestExtractEndpointsFromTreeScopesAxiosInstance(t *testing.T) {
	source := []byte(`
		const loadUsers = async () => {
			const api = axios.create({
				baseURL: "https://api.example.com"
			});

			return api.get("/users");
		};
	`)

	scopes, err := findHTTPCallScopes(source)
	if err != nil {
		t.Fatalf("findHTTPCallScopes returned error: %v", err)
	}

	endpoints, parsed, failed :=
		extractEndpointsFromTreeScopes(scopes)

	if parsed != 1 {
		t.Fatalf("expected 1 parsed scope, got %d", parsed)
	}

	if failed != 0 {
		t.Fatalf("expected 0 failed scopes, got %d", failed)
	}

	if len(endpoints) != 1 {
		t.Fatalf(
			"expected 1 endpoint, got %d: %#v",
			len(endpoints),
			endpoints,
		)
	}

	endpoint := endpoints[0]

	if endpoint.Method != "GET" {
		t.Fatalf("expected GET, got %q", endpoint.Method)
	}

	if endpoint.Path != "https://api.example.com/users" {
		t.Fatalf(
			"unexpected endpoint path %q",
			endpoint.Path,
		)
	}

	if endpoint.Kind != "axios-instance-ast" {
		t.Fatalf(
			"expected axios-instance-ast, got %q",
			endpoint.Kind,
		)
	}
}

func TestExtractEndpointsFromTreeScopesDeduplicatesEndpoints(
	t *testing.T,
) {
	source := []byte(`
		function first() {
			fetch("/api/users");
		}

		function second() {
			fetch("/api/users");
		}
	`)

	scopes, err := findHTTPCallScopes(source)
	if err != nil {
		t.Fatalf("findHTTPCallScopes returned error: %v", err)
	}

	endpoints, parsed, failed :=
		extractEndpointsFromTreeScopes(scopes)

	if parsed != 2 {
		t.Fatalf("expected 2 parsed scopes, got %d", parsed)
	}

	if failed != 0 {
		t.Fatalf("expected 0 failed scopes, got %d", failed)
	}

	if len(endpoints) != 1 {
		t.Fatalf(
			"expected 1 deduplicated endpoint, got %d: %#v",
			len(endpoints),
			endpoints,
		)
	}
}

func TestExtractEndpointsFromTreeScopesContinuesAfterBrokenCode(
	t *testing.T,
) {
	source := []byte(`
		function valid() {
			const endpoint = "/api/health";
			fetch(endpoint);
		}

		function broken( {
			axios.get("/api/broken");
		}
	`)

	scopes, err := findHTTPCallScopes(source)
	if err != nil {
		t.Fatalf("findHTTPCallScopes returned error: %v", err)
	}

	endpoints, parsed, failed :=
		extractEndpointsFromTreeScopes(scopes)

	if parsed == 0 {
		t.Fatal("expected at least one parsed scope")
	}

	found := false

	for _, endpoint := range endpoints {
		if endpoint.Method == "GET" &&
			endpoint.Path == "/api/health" {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf(
			"expected valid endpoint despite broken code: %#v",
			endpoints,
		)
	}

	_ = failed
}

func TestFindHTTPCallScopesRejectsIndexedDBOpen(t *testing.T) {
	source := []byte(`
		function openDatabase() {
			return indexedDB.open("app-database", 1);
		}
	`)

	scopes, err := findHTTPCallScopes(source)
	if err != nil {
		t.Fatalf("findHTTPCallScopes returned error: %v", err)
	}

	if len(scopes) != 0 {
		t.Fatalf(
			"expected indexedDB.open to be ignored, got %d scopes",
			len(scopes),
		)
	}
}

func TestFindHTTPCallScopesAcceptsXHR(t *testing.T) {
	source := []byte(`
		function loadUsers() {
			const xhr = new XMLHttpRequest();
			xhr.open("GET", "/api/users");
		}
	`)

	scopes, err := findHTTPCallScopes(source)
	if err != nil {
		t.Fatalf("findHTTPCallScopes returned error: %v", err)
	}

	if len(scopes) != 1 {
		t.Fatalf("expected 1 XHR scope, got %d", len(scopes))
	}
}

func TestExtractEndpointsHybridResolvesFunctionArgument(t *testing.T) {
	source := []byte(`
		function request(url) {
			return fetch(url);
		}

		request("/api/users");
	`)

	result, err := ExtractEndpointsHybrid(source)
	if err != nil {
		t.Fatalf("extractEndpointsHybrid returned error: %v", err)
	}

	if len(result.Endpoints) != 1 {
		t.Fatalf(
			"expected 1 endpoint, got %d: %#v",
			len(result.Endpoints),
			result.Endpoints,
		)
	}

	endpoint := result.Endpoints[0]

	if endpoint.Method != "GET" {
		t.Fatalf("expected GET, got %q", endpoint.Method)
	}

	if endpoint.Path != "/api/users" {
		t.Fatalf("expected /api/users, got %q", endpoint.Path)
	}

	if endpoint.Kind != "fetch-dataflow-ast" {
		t.Fatalf(
			"expected fetch-dataflow-ast, got %q",
			endpoint.Kind,
		)
	}
}

func TestExtractEndpointsHybridResolvesVariableArgument(t *testing.T) {
	source := []byte(`
		const endpoint = "/api/users";

		function request(url) {
			return fetch(url);
		}

		request(endpoint);
	`)

	result, err := ExtractEndpointsHybrid(source)
	if err != nil {
		t.Fatalf("extractEndpointsHybrid returned error: %v", err)
	}

	if len(result.Endpoints) != 1 {
		t.Fatalf(
			"expected 1 endpoint, got %d: %#v",
			len(result.Endpoints),
			result.Endpoints,
		)
	}

	endpoint := result.Endpoints[0]

	if endpoint.Path != "/api/users" {
		t.Fatalf("expected /api/users, got %q", endpoint.Path)
	}

	if endpoint.Kind != "fetch-dataflow-ast" {
		t.Fatalf(
			"expected fetch-dataflow-ast, got %q",
			endpoint.Kind,
		)
	}
}

func TestExtractEndpointsHybridResolvesObjectPropertyArgument(
	t *testing.T,
) {
	source := []byte(`
		async function request(options) {
			return fetch(options.url);
		}

		request({
			url: "/api/users",
		});
	`)

	result, err := ExtractEndpointsHybrid(source)
	if err != nil {
		t.Fatalf("extractEndpointsHybrid returned error: %v", err)
	}

	if len(result.Endpoints) != 1 {
		t.Fatalf(
			"expected 1 endpoint, got %d: %#v",
			len(result.Endpoints),
			result.Endpoints,
		)
	}

	endpoint := result.Endpoints[0]

	if endpoint.Method != "GET" {
		t.Fatalf("expected GET, got %q", endpoint.Method)
	}

	if endpoint.Path != "/api/users" {
		t.Fatalf("expected /api/users, got %q", endpoint.Path)
	}

	if endpoint.Kind != "fetch-object-dataflow-ast" {
		t.Fatalf(
			"expected fetch-object-dataflow-ast, got %q",
			endpoint.Kind,
		)
	}
}

func TestExtractEndpointsHybridResolvesFetchMethodParameter(
	t *testing.T,
) {
	source := []byte(`
		function request(url, method) {
			return fetch(url, { method });
		}

		request("/api/users", "POST");
	`)

	result, err := ExtractEndpointsHybrid(source)
	if err != nil {
		t.Fatalf("extractEndpointsHybrid returned error: %v", err)
	}

	if len(result.Endpoints) != 1 {
		t.Fatalf(
			"expected 1 endpoint, got %d: %#v",
			len(result.Endpoints),
			result.Endpoints,
		)
	}

	endpoint := result.Endpoints[0]

	if endpoint.Method != "POST" {
		t.Fatalf("expected POST, got %q", endpoint.Method)
	}

	if endpoint.Path != "/api/users" {
		t.Fatalf("expected /api/users, got %q", endpoint.Path)
	}
}

func TestExtractEndpointsHybridResolvesObjectMethodProperty(
	t *testing.T,
) {
	source := []byte(`
		function request(options) {
			return fetch(options.url, {
				method: options.method,
			});
		}

		request({
			url: "/api/users",
			method: "POST",
		});
	`)

	result, err := ExtractEndpointsHybrid(source)
	if err != nil {
		t.Fatalf("extractEndpointsHybrid returned error: %v", err)
	}

	if len(result.Endpoints) != 1 {
		t.Fatalf(
			"expected 1 endpoint, got %d: %#v",
			len(result.Endpoints),
			result.Endpoints,
		)
	}

	endpoint := result.Endpoints[0]

	if endpoint.Method != "POST" {
		t.Fatalf("expected POST, got %q", endpoint.Method)
	}

	if endpoint.Path != "/api/users" {
		t.Fatalf("expected /api/users, got %q", endpoint.Path)
	}

	if endpoint.Kind != "fetch-object-dataflow-ast" {
		t.Fatalf(
			"expected fetch-object-dataflow-ast, got %q",
			endpoint.Kind,
		)
	}
}

func TestExtractEndpointsHybridResolvesArrowFunctionArgument(
	t *testing.T,
) {
	source := []byte(`
		const request = (url, method) => {
			return fetch(url, { method });
		};

		request("/api/users", "POST");
	`)

	result, err := ExtractEndpointsHybrid(source)
	if err != nil {
		t.Fatalf("extractEndpointsHybrid returned error: %v", err)
	}

	if len(result.Endpoints) != 1 {
		t.Fatalf(
			"expected 1 endpoint, got %d: %#v",
			len(result.Endpoints),
			result.Endpoints,
		)
	}

	endpoint := result.Endpoints[0]

	if endpoint.Method != "POST" {
		t.Fatalf("expected POST, got %q", endpoint.Method)
	}

	if endpoint.Path != "/api/users" {
		t.Fatalf("expected /api/users, got %q", endpoint.Path)
	}

	if endpoint.Kind != "fetch-dataflow-ast" {
		t.Fatalf(
			"expected fetch-dataflow-ast, got %q",
			endpoint.Kind,
		)
	}
}

func TestExtractEndpointsHybridResolvesConciseArrowFunction(
	t *testing.T,
) {
	source := []byte(`
		const request = (url, method) =>
			fetch(url, { method });

		request("/api/users", "POST");
	`)

	result, err := ExtractEndpointsHybrid(source)
	if err != nil {
		t.Fatalf("extractEndpointsHybrid returned error: %v", err)
	}

	if len(result.Endpoints) != 1 {
		t.Fatalf(
			"expected 1 endpoint, got %d: %#v",
			len(result.Endpoints),
			result.Endpoints,
		)
	}

	endpoint := result.Endpoints[0]

	if endpoint.Method != "POST" {
		t.Fatalf("expected POST, got %q", endpoint.Method)
	}

	if endpoint.Path != "/api/users" {
		t.Fatalf("expected /api/users, got %q", endpoint.Path)
	}

	if endpoint.Kind != "fetch-dataflow-ast" {
		t.Fatalf(
			"expected fetch-dataflow-ast, got %q",
			endpoint.Kind,
		)
	}
}

func TestExtractEndpointsHybridResolvesConditionalFetchMethod(
	t *testing.T,
) {
	source := []byte(`
		const request = (url, token) =>
			fetch(url, {
				method: token ? "POST" : "DELETE",
			});

		request("/api/session", token);
	`)

	result, err := ExtractEndpointsHybrid(source)
	if err != nil {
		t.Fatalf(
			"extractEndpointsHybrid returned error: %v",
			err,
		)
	}

	methods := make(map[string]bool)

	for _, endpoint := range result.Endpoints {
		if endpoint.Path == "/api/session" {
			methods[endpoint.Method] = true
		}
	}

	if !methods["POST"] {
		t.Fatalf(
			"expected POST endpoint, got %#v",
			result.Endpoints,
		)
	}

	if !methods["DELETE"] {
		t.Fatalf(
			"expected DELETE endpoint, got %#v",
			result.Endpoints,
		)
	}
}

func TestExtractEndpointsHybridResolvesRequestConstructor(
	t *testing.T,
) {
	source := []byte(`
		const request = () => {
			fetch(new Request("/api/users", {
				method: "POST",
			}));
		};

		request();
	`)

	result, err := ExtractEndpointsHybrid(source)
	if err != nil {
		t.Fatalf(
			"extractEndpointsHybrid returned error: %v",
			err,
		)
	}

	found := false

	for _, endpoint := range result.Endpoints {
		if endpoint.Path == "/api/users" &&
			endpoint.Method == "POST" {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf(
			"expected POST /api/users, got %#v",
			result.Endpoints,
		)
	}
}

func TestExtractEndpointsHybridResolvesDynamicRequestProperties(
	t *testing.T,
) {
	source := []byte(`
		function request(config) {
			return fetch(new Request(config.url, {
				method: config.method,
			}));
		}

		request({
			url: "/api/users",
			method: "POST",
		});
	`)

	result, err := ExtractEndpointsHybrid(source)
	if err != nil {
		t.Fatalf(
			"extractEndpointsHybrid returned error: %v",
			err,
		)
	}

	found := false

	for _, endpoint := range result.Endpoints {
		if endpoint.Path == "/api/users" &&
			endpoint.Method == "POST" {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf(
			"expected POST /api/users, got %#v",
			result.Endpoints,
		)
	}
}

func TestExtractEndpointsHybridResolvesRequestInstanceFields(
	t *testing.T,
) {
	source := []byte(`
		class Client {
			constructor(url, method) {
				this.url = url;
				this.method = method;
			}

			send() {
				return fetch(new Request(this.url, {
					method: this.method,
				}));
			}
		}

		const client = new Client(
			"/api/users",
			"POST",
		);

		client.send();
	`)

	result, err := ExtractEndpointsHybrid(source)
	if err != nil {
		t.Fatalf(
			"extractEndpointsHybrid returned error: %v",
			err,
		)
	}

	found := false

	for _, endpoint := range result.Endpoints {
		if endpoint.Path == "/api/users" &&
			endpoint.Method == "POST" {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf(
			"expected POST /api/users, got %#v",
			result.Endpoints,
		)
	}
}

func TestExtractEndpointsHybridResolvesPrototypeInstanceFields(
	t *testing.T,
) {
	source := []byte(`
		function Client(url, method) {
			this.url = url;
			this.method = method;
		}

		Client.prototype.send = function() {
			return fetch(new Request(this.url, {
				method: this.method,
			}));
		};

		const client = new Client(
			"/api/users",
			"POST",
		);

		client.send();
	`)

	result, err := ExtractEndpointsHybrid(source)
	if err != nil {
		t.Fatalf(
			"extractEndpointsHybrid returned error: %v",
			err,
		)
	}

	for _, endpoint := range result.Endpoints {
		if endpoint.Path == "/api/users" &&
			endpoint.Method == "POST" {
			return
		}
	}

	t.Fatalf(
		"expected POST /api/users, got %#v",
		result.Endpoints,
	)
}

func TestExtractEndpointsHybridResolvesRequestOptionsVariable(
	t *testing.T,
) {
	source := []byte(`
		function Client(url, method) {
			this.url = url;
			this.method = method;
		}

		Client.prototype.send = function() {
			const options = {
				method: this.method,
			};

			return fetch(
				new Request(this.url, options),
			);
		};

		const client = new Client(
			"/api/users",
			"POST",
		);

		client.send();
	`)

	result, err := ExtractEndpointsHybrid(source)
	if err != nil {
		t.Fatalf(
			"extractEndpointsHybrid returned error: %v",
			err,
		)
	}

	for _, endpoint := range result.Endpoints {
		if endpoint.Path == "/api/users" &&
			endpoint.Method == "POST" {
			return
		}
	}

	t.Fatalf(
		"expected POST /api/users, got %#v",
		result.Endpoints,
	)
}

func TestExtractEndpointsHybridResolvesMemberFetchCall(
	t *testing.T,
) {
	source := []byte(`
		class Client {
			constructor(url, method) {
				this.url = url;
				this.method = method;
				this.transport = window;
			}

			send() {
				const options = {
					method: this.method,
				};

				return (this.transport || window).fetch(
					new Request(this.url, options),
				);
			}
		}

		const client = new Client(
			"/api/users",
			"POST",
		);

		client.send();
	`)

	result, err := ExtractEndpointsHybrid(source)
	if err != nil {
		t.Fatalf(
			"extractEndpointsHybrid returned error: %v",
			err,
		)
	}

	for _, endpoint := range result.Endpoints {
		if endpoint.Path == "/api/users" &&
			endpoint.Method == "POST" {
			return
		}
	}

	t.Fatalf(
		"expected POST /api/users, got %#v",
		result.Endpoints,
	)
}

func TestExtractEndpointsHybridResolvesInstanceMutatorMethod(
	t *testing.T,
) {
	source := []byte(`
		function Client() {}

		Client.prototype.open = function(method, url) {
			this.method = method;
			this.url = url;
		};

		Client.prototype.send = function() {
			const options = {
				method: this.method,
			};

			return window.fetch(
				new Request(this.url, options),
			);
		};

		const client = new Client();

		client.open("POST", "/api/users");
		client.send();
	`)

	result, err := ExtractEndpointsHybrid(source)
	if err != nil {
		t.Fatalf(
			"extractEndpointsHybrid returned error: %v",
			err,
		)
	}

	for _, endpoint := range result.Endpoints {
		if endpoint.Path == "/api/users" &&
			endpoint.Method == "POST" {
			return
		}
	}

	t.Fatalf(
		"expected POST /api/users, got %#v",
		result.Endpoints,
	)
}

func TestExtractEndpointsHybridResolvesPrototypeAlias(
	t *testing.T,
) {
	source := []byte(`
		function Client() {}

		let proto = Client.prototype;

		proto.open = function(method, url) {
			this.method = method;
			this.url = url;
		};

		proto.send = function() {
			const options = {
				method: this.method,
			};

			return window.fetch(
				new Request(this.url, options),
			);
		};

		const client = new Client();

		client.open("POST", "/api/users");
		client.send();
	`)

	result, err := ExtractEndpointsHybrid(source)
	if err != nil {
		t.Fatalf(
			"extractEndpointsHybrid returned error: %v",
			err,
		)
	}

	for _, endpoint := range result.Endpoints {
		if endpoint.Path == "/api/users" &&
			endpoint.Method == "POST" {
			return
		}
	}

	t.Fatalf(
		"expected POST /api/users, got %#v",
		result.Endpoints,
	)
}

func TestExtractEndpointsHybridResolvesAssignedPrototypeAlias(
	t *testing.T,
) {
	source := []byte(`
		function Client() {}

		let proto;
		proto = Client.prototype;

		proto.open = function(method, url) {
			this.method = method;
			this.url = url;
		};

		proto.send = function() {
			const options = {
				method: this.method,
			};

			return window.fetch(
				new Request(this.url, options),
			);
		};

		const client = new Client();

		client.open("POST", "/api/users");
		client.send();
	`)

	result, err := ExtractEndpointsHybrid(source)
	if err != nil {
		t.Fatalf(
			"extractEndpointsHybrid returned error: %v",
			err,
		)
	}

	for _, endpoint := range result.Endpoints {
		if endpoint.Path == "/api/users" &&
			endpoint.Method == "POST" {
			return
		}
	}

	t.Fatalf(
		"expected POST /api/users, got %#v",
		result.Endpoints,
	)
}

func TestExtractEndpointsHybridResolvesFactoryCreatedInstance(t *testing.T) {
	source := []byte(`
		function Client() {
			this.method = "GET";
			this.url = "";
		}

		let proto = Client.prototype;

		proto.open = function(method, url) {
			this.method = method;
			this.url = url;
		};

		proto.send = function() {
			return fetch(
				new Request(this.url, {
					method: this.method,
				}),
			);
		};

		function Factory() {}

		Factory.prototype.create = function() {
			return new Client();
		};

		const factory = new Factory();
		const client = factory.create();

		client.open("POST", "/api/users");
		client.send();
	`)

	result, err := ExtractEndpointsHybrid(source)
	if err != nil {
		t.Fatalf(
			"extractEndpointsHybrid returned error: %v",
			err,
		)
	}

	for _, endpoint := range result.Endpoints {
		if endpoint.Path == "/api/users" &&
			endpoint.Method == "POST" {
			return
		}
	}

	t.Fatalf(
		"expected POST /api/users, got %#v",
		result.Endpoints,
	)
}

func TestExtractEndpointsHybridResolvesFactoryStoredInConstructorField(
	t *testing.T,
) {
	source := []byte(`
		function Client() {
			this.method = "GET";
			this.url = "";
		}

		let clientProto = Client.prototype;

		clientProto.open = function(method, url) {
			this.method = method;
			this.url = url;
		};

		clientProto.send = function() {
			return fetch(
				new Request(this.url, {
					method: this.method,
				}),
			);
		};

		function Factory() {}

		Factory.prototype.create = function() {
			return new Client();
		};

		function Wrapper(factory) {
			this.factory = factory;
			this.client = null;
		}

		Wrapper.prototype.request = function(url, method) {
			this.client = this.factory.create();
			this.client.open(method, String(url));
			this.client.send();
		};

		let wrapper;
		const enabled = true;
		wrapper = enabled
			? new Wrapper(new Factory())
			: new Wrapper(null);

		wrapper.request(
			"/api/users",
			"POST",
		);
	`)

	result, err := ExtractEndpointsHybrid(source)
	if err != nil {
		t.Fatalf(
			"extractEndpointsHybrid returned error: %v",
			err,
		)
	}

	for _, endpoint := range result.Endpoints {
		if endpoint.Path == "/api/users" &&
			endpoint.Method == "POST" {
			return
		}
	}

	t.Fatalf(
		"expected POST /api/users, got %#v",
		result.Endpoints,
	)
}

func TestExtractEndpointsHybridResolvesReturnedInstanceStoredInObjectField(
	t *testing.T,
) {
	source := []byte(`
		function Client() {}

		Client.prototype.request = function(url, method) {
			return fetch(url, {
				method: method,
			});
		};

		function createClient() {
			return new Client();
		}

		function Transport() {
			this.client = null;
			this.url = "";
			this.method = "GET";
		}

		Transport.prototype.send = function(url, method) {
			this.url = url;
			this.method = method;
			this.client = createClient();
			this.client.request(
				this.url,
				this.method,
			);
		};

		const transport = new Transport();

		transport.send(
			"/api/users",
			"POST",
		);
	`)

	result, err := ExtractEndpointsHybrid(source)
	if err != nil {
		t.Fatalf(
			"extractEndpointsHybrid returned error: %v",
			err,
		)
	}

	for _, endpoint := range result.Endpoints {
		if endpoint.Path == "/api/users" &&
			endpoint.Method == "POST" {
			return
		}
	}

	t.Fatalf(
		"expected POST /api/users, got %#v",
		result.Endpoints,
	)
}

func TestExtractEndpointsHybridRecordsDynamicHTTPFlow(
	t *testing.T,
) {
	source := []byte(`
		function request(url, method) {
			return fetch(url, {
				method: method,
			});
		}

		request(runtimeURL, runtimeMethod);
	`)

	result, err := ExtractEndpointsHybrid(source)
	if err != nil {
		t.Fatalf(
			"extractEndpointsHybrid returned error: %v",
			err,
		)
	}

	if len(result.Endpoints) != 0 {
		t.Fatalf(
			"expected no concrete endpoints, got %#v",
			result.Endpoints,
		)
	}

	if len(result.HTTPFlows) != 1 {
		t.Fatalf(
			"expected one symbolic HTTP flow, got %#v",
			result.HTTPFlows,
		)
	}

	flow := result.HTTPFlows[0]

	if flow.Function != "request" {
		t.Fatalf(
			"expected function request, got %q",
			flow.Function,
		)
	}

	if flow.Sink != "fetch" {
		t.Fatalf(
			"expected fetch sink, got %q",
			flow.Sink,
		)
	}

	if flow.URLSource != "runtimeURL" ||
		!flow.DynamicURL {
		t.Fatalf(
			"unexpected URL flow: %#v",
			flow,
		)
	}

	if flow.MethodSource != "runtimeMethod" ||
		!flow.DynamicMethod {
		t.Fatalf(
			"unexpected method flow: %#v",
			flow,
		)
	}
}

func TestFindNamedDataFlowFunctionsSkipsDestructuredArrowBinding(t *testing.T) {
	source := []byte(`
		const { run } = (url) => {
			fetch(url);
		};

		run("/api/users");
	`)

	result, err := ExtractEndpointsHybrid(source)
	if err != nil {
		t.Fatalf("extractEndpointsHybrid returned error: %v", err)
	}

	if len(result.Endpoints) != 0 {
		t.Fatalf(
			"expected destructured binding to produce no endpoint, got %#v",
			result.Endpoints,
		)
	}
}
