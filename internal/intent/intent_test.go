package intent

import (
	"testing"
)

// -------------------------------------------------------
// Scan — tokenization
// -------------------------------------------------------

func TestScan_WordToken(t *testing.T) {
	tokens := Scan([]string{"json"})
	if len(tokens) != 1 || tokens[0].Type != TokenWord {
		t.Errorf("expected 1 TokenWord, got %v", tokens)
	}
	if tokens[0].Value != "json" {
		t.Errorf("expected Value=json, got %q", tokens[0].Value)
	}
}

func TestScan_KeyValueToken(t *testing.T) {
	tokens := Scan([]string{"name=Alice"})
	if len(tokens) != 1 || tokens[0].Type != TokenKeyValue {
		t.Errorf("expected 1 TokenKeyValue, got %v", tokens)
	}
	if tokens[0].Key != "name" || tokens[0].Value != "Alice" {
		t.Errorf("expected key=name value=Alice, got key=%q value=%q", tokens[0].Key, tokens[0].Value)
	}
}

func TestScan_KeyValueCaseNormalizedKey(t *testing.T) {
	tokens := Scan([]string{"NAME=Alice"})
	if tokens[0].Key != "name" {
		t.Errorf("expected key lowercased to 'name', got %q", tokens[0].Key)
	}
}

func TestScan_FlagToken(t *testing.T) {
	tokens := Scan([]string{"--follow"})
	if len(tokens) != 1 || tokens[0].Type != TokenFlag {
		t.Errorf("expected 1 TokenFlag, got %v", tokens)
	}
}

func TestScan_FlagWithNextArg(t *testing.T) {
	tokens := Scan([]string{"-h", "Content-Type: application/json"})
	if len(tokens) != 1 || tokens[0].Type != TokenFlag {
		t.Errorf("expected flag to consume next arg, got %v", tokens)
	}
	if tokens[0].Raw != "-h\x00Content-Type: application/json" {
		t.Errorf("unexpected raw: %q", tokens[0].Raw)
	}
}

func TestScan_CookieToken(t *testing.T) {
	tokens := Scan([]string{"cookie:session=abc123"})
	if len(tokens) != 1 || tokens[0].Type != TokenCookie {
		t.Errorf("expected 1 TokenCookie, got %v", tokens)
	}
	if tokens[0].Key != "session" || tokens[0].Value != "abc123" {
		t.Errorf("expected key=session value=abc123, got %q=%q", tokens[0].Key, tokens[0].Value)
	}
}

func TestScan_CookiePrefixCaseInsensitive(t *testing.T) {
	tokens := Scan([]string{"Cookie:token=xyz"})
	if len(tokens) != 1 || tokens[0].Type != TokenCookie {
		t.Errorf("expected TokenCookie for Cookie: prefix, got %v", tokens)
	}
}

func TestScan_AuthToken(t *testing.T) {
	tokens := Scan([]string{"bearer=mytoken123"})
	if len(tokens) != 1 || tokens[0].Type != TokenAuth {
		t.Errorf("expected 1 TokenAuth, got %v", tokens)
	}
	if tokens[0].Value != "mytoken123" {
		t.Errorf("expected Value=mytoken123, got %q", tokens[0].Value)
	}
}

func TestScan_TokenPrefix(t *testing.T) {
	tokens := Scan([]string{"token=mytoken"})
	if tokens[0].Type != TokenAuth {
		t.Errorf("expected TokenAuth for token= prefix")
	}
}

func TestScan_AuthPrefix(t *testing.T) {
	tokens := Scan([]string{"auth=mytoken"})
	if tokens[0].Type != TokenAuth {
		t.Errorf("expected TokenAuth for auth= prefix")
	}
}

func TestScan_MultipleTokens(t *testing.T) {
	tokens := Scan([]string{"json", "name=Alice", "--follow", "bearer=tok"})
	if len(tokens) != 4 {
		t.Errorf("expected 4 tokens, got %d", len(tokens))
	}
	if tokens[0].Type != TokenWord {
		t.Errorf("first token should be Word")
	}
	if tokens[1].Type != TokenKeyValue {
		t.Errorf("second token should be KeyValue")
	}
	if tokens[2].Type != TokenFlag {
		t.Errorf("third token should be Flag")
	}
	if tokens[3].Type != TokenAuth {
		t.Errorf("fourth token should be Auth")
	}
}

// -------------------------------------------------------
// TokensToArgs
// -------------------------------------------------------

func TestTokensToArgs_FlagWithValue(t *testing.T) {
	tokens := []Token{
		{Type: TokenFlag, Raw: "-H\x00Content-Type: application/json"},
	}
	args := TokensToArgs(tokens)
	if len(args) != 2 {
		t.Errorf("expected 2 args, got %v", args)
	}
	if args[0] != "-H" || args[1] != "Content-Type: application/json" {
		t.Errorf("unexpected args: %v", args)
	}
}

func TestTokensToArgs_SimpleFlag(t *testing.T) {
	tokens := []Token{
		{Type: TokenFlag, Raw: "--follow"},
	}
	args := TokensToArgs(tokens)
	if len(args) != 1 || args[0] != "--follow" {
		t.Errorf("expected [--follow], got %v", args)
	}
}

func TestTokensToArgs_WordToken(t *testing.T) {
	tokens := []Token{
		{Type: TokenWord, Raw: "http://example.com"},
	}
	args := TokensToArgs(tokens)
	if len(args) != 1 || args[0] != "http://example.com" {
		t.Errorf("expected URL arg, got %v", args)
	}
}

// -------------------------------------------------------
// inferJSONValue
// -------------------------------------------------------

func TestInferJSONValue_String(t *testing.T) {
	got := inferJSONValue("hello")
	if s, ok := got.(string); !ok || s != "hello" {
		t.Errorf("expected string 'hello', got %v (%T)", got, got)
	}
}

func TestInferJSONValue_Int(t *testing.T) {
	got := inferJSONValue("42")
	if i, ok := got.(int); !ok || i != 42 {
		t.Errorf("expected int 42, got %v (%T)", got, got)
	}
}

func TestInferJSONValue_Float(t *testing.T) {
	got := inferJSONValue("3.14")
	if f, ok := got.(float64); !ok || f != 3.14 {
		t.Errorf("expected float64 3.14, got %v (%T)", got, got)
	}
}

func TestInferJSONValue_BoolTrue(t *testing.T) {
	got := inferJSONValue("true")
	if b, ok := got.(bool); !ok || !b {
		t.Errorf("expected bool true, got %v (%T)", got, got)
	}
}

func TestInferJSONValue_BoolFalse(t *testing.T) {
	got := inferJSONValue("false")
	if b, ok := got.(bool); !ok || b {
		t.Errorf("expected bool false, got %v (%T)", got, got)
	}
}

func TestInferJSONValue_Null(t *testing.T) {
	got := inferJSONValue("null")
	if got != nil {
		t.Errorf("expected nil for 'null', got %v", got)
	}
}

func TestInferJSONValue_NullCaseInsensitive(t *testing.T) {
	got := inferJSONValue("NULL")
	if got != nil {
		t.Errorf("expected nil for 'NULL', got %v", got)
	}
}

// -------------------------------------------------------
// insertJSONPath
// -------------------------------------------------------

func TestInsertJSONPath_TopLevel(t *testing.T) {
	root := map[string]any{}
	insertJSONPath(root, "name", "Alice")
	if root["name"] != "Alice" {
		t.Errorf("expected root[name]=Alice, got %v", root["name"])
	}
}

func TestInsertJSONPath_Nested(t *testing.T) {
	root := map[string]any{}
	insertJSONPath(root, "user.name", "Alice")
	user, ok := root["user"].(map[string]any)
	if !ok {
		t.Fatalf("expected root[user] to be map, got %T", root["user"])
	}
	if user["name"] != "Alice" {
		t.Errorf("expected user[name]=Alice, got %v", user["name"])
	}
}

func TestInsertJSONPath_DuplicateKeyMakesArray(t *testing.T) {
	root := map[string]any{}
	insertJSONPath(root, "tag", "go")
	insertJSONPath(root, "tag", "backend")

	arr, ok := root["tag"].([]any)
	if !ok {
		t.Fatalf("expected array for duplicate key, got %T", root["tag"])
	}
	if len(arr) != 2 {
		t.Errorf("expected 2 elements, got %d", len(arr))
	}
}

func TestInsertJSONPath_DeepNesting(t *testing.T) {
	root := map[string]any{}
	insertJSONPath(root, "a.b.c", "deep")
	a := root["a"].(map[string]any)
	b := a["b"].(map[string]any)
	if b["c"] != "deep" {
		t.Errorf("expected deep value, got %v", b["c"])
	}
}

// -------------------------------------------------------
// isProfile / isContent / isBooleanWord
// -------------------------------------------------------

func TestIsProfile(t *testing.T) {
	valid := []string{"firefox", "chrome", "api", "curl", "browser"}
	for _, v := range valid {
		if _, ok := isProfile(v); !ok {
			t.Errorf("expected isProfile(%q) to be valid", v)
		}
	}
	if _, ok := isProfile("unknown"); ok {
		t.Error("expected isProfile('unknown') to be invalid")
	}
}

func TestIsContent(t *testing.T) {
	for _, v := range []string{"json", "xml", "form"} {
		if _, ok := isContent(v); !ok {
			t.Errorf("expected isContent(%q) to be valid", v)
		}
	}
	if _, ok := isContent("html"); ok {
		t.Error("expected isContent('html') to be invalid")
	}
}

func TestIsBooleanWord(t *testing.T) {
	for _, v := range []string{"csrf", "auto-cookie"} {
		if _, ok := isBooleanWord(v); !ok {
			t.Errorf("expected isBooleanWord(%q) to be valid", v)
		}
	}
	if _, ok := isBooleanWord("random"); ok {
		t.Error("expected isBooleanWord('random') to be invalid")
	}
}

func TestIsReconProfile(t *testing.T) {
	for _, v := range []string{"http", "web", "api"} {
		if _, ok := isReconProfile(v); !ok {
			t.Errorf("expected isReconProfile(%q) to be valid", v)
		}
	}
	if _, ok := isReconProfile("browser"); ok {
		t.Error("expected isReconProfile('browser') to be invalid")
	}
}
