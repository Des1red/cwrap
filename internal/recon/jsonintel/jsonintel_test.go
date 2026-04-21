package jsonintel

import (
	"cwrap/internal/recon/knowledge"
	"testing"
)

func newEntAndKnowledge() (*knowledge.Entity, *knowledge.Knowledge) {
	k := knowledge.New("http://example.com")
	ent := k.Entity("http://example.com/api/test")
	return ent, k
}

// -------------------------------------------------------
// Basic extraction
// -------------------------------------------------------

func TestExtractParams_TopLevelKeysRegistered(t *testing.T) {
	ent, k := newEntAndKnowledge()
	data := []byte(`{"id":1,"username":"alice","email":"alice@example.com"}`)

	ExtractParams(ent, k, data)

	for _, name := range []string{"id", "username", "email"} {
		p := ent.Params[name]
		if p == nil {
			t.Errorf("expected param %q to be registered", name)
			continue
		}
		if !p.Sources[knowledge.ParamJSON] {
			t.Errorf("param %q expected source ParamJSON", name)
		}
	}
}

func TestExtractParams_ArrayFirstElementWalked(t *testing.T) {
	ent, k := newEntAndKnowledge()
	data := []byte(`[{"post_id":1,"title":"First"},{"post_id":2,"title":"Second"}]`)

	ExtractParams(ent, k, data)

	for _, name := range []string{"post_id", "title"} {
		if ent.Params[name] == nil {
			t.Errorf("expected param %q from array first element", name)
		}
	}
}

func TestExtractParams_EmptyArrayHandled(t *testing.T) {
	ent, k := newEntAndKnowledge()

	// should not panic or error
	ExtractParams(ent, k, []byte(`[]`))

	if len(ent.Params) != 0 {
		t.Errorf("expected no params from empty array, got %v", ent.Params)
	}
}

func TestExtractParams_InvalidJSONHandled(t *testing.T) {
	ent, k := newEntAndKnowledge()

	// should not panic
	ExtractParams(ent, k, []byte(`{not valid`))

	if len(ent.Params) != 0 {
		t.Errorf("expected no params from invalid JSON, got %v", ent.Params)
	}
}

// -------------------------------------------------------
// Reflection key filtering
// -------------------------------------------------------

func TestExtractParams_ReflectionKeysSkipped(t *testing.T) {
	ent, k := newEntAndKnowledge()
	data := []byte(`{"headers":{},"origin":"http://example.com","url":"/test","args":{},"id":1}`)

	ExtractParams(ent, k, data)

	for _, skip := range []string{"headers", "origin", "url", "args"} {
		if ent.Params[skip] != nil {
			t.Errorf("reflection key %q should not be registered", skip)
		}
	}
	// "id" should still be registered
	if ent.Params["id"] == nil {
		t.Error("expected non-reflection key 'id' to be registered")
	}
}

func TestExtractParams_ErrorEnvelopeKeysSkipped(t *testing.T) {
	ent, k := newEntAndKnowledge()
	data := []byte(`{"error":"not found","message":"resource missing","code":404,"status":404,"trace":"..."}`)

	ExtractParams(ent, k, data)

	for _, skip := range []string{"error", "message", "code", "status", "trace"} {
		if ent.Params[skip] != nil {
			t.Errorf("error envelope key %q should not be registered", skip)
		}
	}
}

// -------------------------------------------------------
// Depth limit
// -------------------------------------------------------

func TestExtractParams_DepthLimitEnforced(t *testing.T) {
	ent, k := newEntAndKnowledge()
	// depth 0: user → registered
	// depth 1: id, name → registered
	// depth 2: city → registered
	// depth 3: zip → should NOT be registered
	data := []byte(`{
		"user": {
			"id": 1,
			"name": "Alice",
			"address": {
				"city": "London",
				"geo": {
					"zip": "SW1A"
				}
			}
		}
	}`)

	ExtractParams(ent, k, data)

	if ent.Params["user"] == nil {
		t.Error("expected depth-0 key 'user' to be registered")
	}
	if ent.Params["id"] == nil {
		t.Error("expected depth-1 key 'id' to be registered")
	}
	if ent.Params["city"] == nil {
		t.Error("expected depth-2 key 'city' to be registered")
	}
	if ent.Params["zip"] != nil {
		t.Error("depth-3 key 'zip' should not be registered — too deep")
	}
}

// -------------------------------------------------------
// Classification
// -------------------------------------------------------

func TestExtractParams_IDLikeParamClassified(t *testing.T) {
	ent, k := newEntAndKnowledge()
	data := []byte(`{"user_id":1,"account_id":2,"name":"Alice"}`)

	ExtractParams(ent, k, data)

	for _, name := range []string{"user_id", "account_id"} {
		p := ent.Params[name]
		if p == nil {
			t.Fatalf("expected param %q", name)
		}
		if !p.IDLike {
			t.Errorf("expected param %q to be classified as IDLike", name)
		}
	}

	// "name" should not be IDLike
	if p := ent.Params["name"]; p != nil && p.IDLike {
		t.Error("param 'name' should not be IDLike")
	}
}

func TestExtractParams_TokenLikeParamClassified(t *testing.T) {
	ent, k := newEntAndKnowledge()
	data := []byte(`{"access_token":"abc","refresh_token":"def","id":1}`)

	ExtractParams(ent, k, data)

	for _, name := range []string{"access_token", "refresh_token"} {
		p := ent.Params[name]
		if p == nil {
			t.Fatalf("expected param %q", name)
		}
		if !p.TokenLike {
			t.Errorf("expected param %q to be classified as TokenLike", name)
		}
	}
}

// -------------------------------------------------------
// Global param registration
// -------------------------------------------------------

func TestExtractParams_GlobalParamRegistered(t *testing.T) {
	ent, k := newEntAndKnowledge()
	data := []byte(`{"unique_field_xyz":1}`)

	ExtractParams(ent, k, data)

	if !k.Params["unique_field_xyz"] {
		t.Error("expected param to be registered in global knowledge.Params")
	}
}
