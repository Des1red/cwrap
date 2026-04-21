package canonicalize

import (
	"bytes"
	"testing"
)

// -------------------------------------------------------
// JSON
// -------------------------------------------------------

func TestJSON_SameSchemaEqualsAfterNormalization(t *testing.T) {
	a := []byte(`{"id":1,"name":"Alice","role":"member"}`)
	b := []byte(`{"id":2,"name":"Bob","role":"owner"}`)

	na, err := JSON(a, "")
	if err != nil {
		t.Fatalf("JSON(a) error: %v", err)
	}
	nb, err := JSON(b, "")
	if err != nil {
		t.Fatalf("JSON(b) error: %v", err)
	}

	if !bytes.Equal(na, nb) {
		t.Errorf("same schema different values should normalize equal\ngot a: %s\ngot b: %s", na, nb)
	}
}

func TestJSON_DifferentSchemaDiffersAfterNormalization(t *testing.T) {
	// one has "salary" field, other does not
	a := []byte(`{"id":1,"name":"Alice","salary":50000}`)
	b := []byte(`{"id":2,"name":"Bob"}`)

	na, _ := JSON(a, "")
	nb, _ := JSON(b, "")

	if bytes.Equal(na, nb) {
		t.Error("different schemas should not normalize equal")
	}
}

func TestJSON_DifferentTypesDiffer(t *testing.T) {
	// "active" is bool in one, string in other
	a := []byte(`{"id":1,"active":true}`)
	b := []byte(`{"id":2,"active":"yes"}`)

	na, _ := JSON(a, "")
	nb, _ := JSON(b, "")

	if bytes.Equal(na, nb) {
		t.Error("different value types should not normalize equal")
	}
}

func TestJSON_ArraysCollapsedToFirstElement(t *testing.T) {
	// 3 items vs 1 item — same schema, should be equal
	a := []byte(`[{"id":1,"name":"Alice"},{"id":2,"name":"Bob"},{"id":3,"name":"Carol"}]`)
	b := []byte(`[{"id":99,"name":"Zara"}]`)

	na, _ := JSON(a, "")
	nb, _ := JSON(b, "")

	if !bytes.Equal(na, nb) {
		t.Errorf("arrays with same element schema should normalize equal\na: %s\nb: %s", na, nb)
	}
}

func TestJSON_EmptyArrayEqualsEmptyArray(t *testing.T) {
	a := []byte(`[]`)
	b := []byte(`[]`)

	na, _ := JSON(a, "")
	nb, _ := JSON(b, "")

	if !bytes.Equal(na, nb) {
		t.Error("empty arrays should normalize equal")
	}
}

func TestJSON_NestedObjectNormalized(t *testing.T) {
	a := []byte(`{"user":{"id":1,"email":"a@b.com"}}`)
	b := []byte(`{"user":{"id":2,"email":"c@d.com"}}`)

	na, _ := JSON(a, "")
	nb, _ := JSON(b, "")

	if !bytes.Equal(na, nb) {
		t.Errorf("nested objects with same schema should normalize equal\na: %s\nb: %s", na, nb)
	}
}

func TestJSON_InvalidJSONReturnsError(t *testing.T) {
	_, err := JSON([]byte(`{not valid json`), "")
	if err == nil {
		t.Error("expected error for invalid JSON input")
	}
}

func TestJSON_NullValuePreserved(t *testing.T) {
	a := []byte(`{"id":1,"deleted_at":null}`)
	b := []byte(`{"id":2,"deleted_at":null}`)

	na, _ := JSON(a, "")
	nb, _ := JSON(b, "")

	if !bytes.Equal(na, nb) {
		t.Error("null values should normalize equal across responses")
	}
}

// -------------------------------------------------------
// HTML
// -------------------------------------------------------

func TestHTML_SameStructureDifferentContentEqualsAfterNormalization(t *testing.T) {
	a := []byte(`<!doctype html><html><body><h1>Welcome Alice</h1><p>You have 5 messages</p></body></html>`)
	b := []byte(`<!doctype html><html><body><h1>Welcome Bob</h1><p>You have 12 messages</p></body></html>`)

	na := HTML(a)
	nb := HTML(b)

	if !bytes.Equal(na, nb) {
		t.Errorf("same DOM structure different text should normalize equal\na: %s\nb: %s", na, nb)
	}
}

func TestHTML_DifferentStructureDiffersAfterNormalization(t *testing.T) {
	a := []byte(`<!doctype html><html><body><h1>Title</h1><p>Text</p></body></html>`)
	b := []byte(`<!doctype html><html><body><h1>Title</h1><p>Text</p><div class="extra">Extra</div></body></html>`)

	na := HTML(a)
	nb := HTML(b)

	if bytes.Equal(na, nb) {
		t.Error("different DOM structures should not normalize equal")
	}
}

func TestHTML_ScriptContentStripped(t *testing.T) {
	a := []byte(`<html><body><script>var token="secret123";</script><p>content</p></body></html>`)
	b := []byte(`<html><body><script>var token="different456";</script><p>content</p></body></html>`)

	na := HTML(a)
	nb := HTML(b)

	if !bytes.Equal(na, nb) {
		t.Errorf("script content should be stripped — different tokens should normalize equal\na: %s\nb: %s", na, nb)
	}
}

func TestHTML_AttributeValuesStripped(t *testing.T) {
	a := []byte(`<html><body><a href="/user/123">Alice</a></body></html>`)
	b := []byte(`<html><body><a href="/user/456">Bob</a></body></html>`)

	na := HTML(a)
	nb := HTML(b)

	if !bytes.Equal(na, nb) {
		t.Errorf("attribute values should be stripped\na: %s\nb: %s", na, nb)
	}
}

// -------------------------------------------------------
// StripNumbers
// -------------------------------------------------------

func TestStripNumbers_ReplacesDigitsWithHash(t *testing.T) {
	input := []byte("user_id=123&page=4")
	got := StripNumbers(input)
	want := []byte("user_id=###&page=#")

	if !bytes.Equal(got, want) {
		t.Errorf("StripNumbers(%q) = %q want %q", input, got, want)
	}
}

func TestStripNumbers_NoDigitsUnchanged(t *testing.T) {
	input := []byte("hello world")
	got := StripNumbers(input)
	if !bytes.Equal(got, input) {
		t.Errorf("StripNumbers with no digits should be unchanged, got %q", got)
	}
}

func TestStripNumbers_DoesNotMutateInput(t *testing.T) {
	input := []byte("abc123")
	original := make([]byte, len(input))
	copy(original, input)
	StripNumbers(input)
	if !bytes.Equal(input, original) {
		t.Error("StripNumbers should not mutate the input slice")
	}
}
