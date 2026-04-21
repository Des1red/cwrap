package paramintel

import (
	"cwrap/internal/recon/knowledge"
	"testing"
)

func newParam(name string) (*knowledge.Entity, *knowledge.ParamIntel) {
	ent := knowledge.NewEntity("http://example.com/test")
	ent.AddParam(name, knowledge.ParamJSON)
	return ent, ent.Params[name]
}

// -------------------------------------------------------
// IDLike classification
// -------------------------------------------------------

func TestClassifyParam_ExactID(t *testing.T) {
	ent, p := newParam("id")
	ClassifyParam(ent, p)
	if !p.IDLike {
		t.Error("expected 'id' to be IDLike")
	}
}

func TestClassifyParam_SuffixID(t *testing.T) {
	for _, name := range []string{"user_id", "post_id", "account_id", "owner_id"} {
		ent, p := newParam(name)
		ClassifyParam(ent, p)
		if !p.IDLike {
			t.Errorf("expected %q to be IDLike", name)
		}
	}
}

func TestClassifyParam_ContainsUser(t *testing.T) {
	ent, p := newParam("username")
	ClassifyParam(ent, p)
	if !p.IDLike {
		t.Error("expected 'username' to be IDLike (contains 'user')")
	}
}

func TestClassifyParam_ContainsAccount(t *testing.T) {
	ent, p := newParam("account_name")
	ClassifyParam(ent, p)
	if !p.IDLike {
		t.Error("expected 'account_name' to be IDLike (contains 'account')")
	}
}

func TestClassifyParam_NotIDLike(t *testing.T) {
	for _, name := range []string{"title", "body", "created_at", "email", "role"} {
		ent, p := newParam(name)
		ClassifyParam(ent, p)
		if p.IDLike {
			t.Errorf("expected %q NOT to be IDLike", name)
		}
	}
}

// -------------------------------------------------------
// TokenLike classification
// -------------------------------------------------------

func TestClassifyParam_TokenLike(t *testing.T) {
	for _, name := range []string{"access_token", "refresh_token", "session_id", "auth_key", "api_key"} {
		ent, p := newParam(name)
		ClassifyParam(ent, p)
		if !p.TokenLike {
			t.Errorf("expected %q to be TokenLike", name)
		}
	}
}

func TestClassifyParam_NotTokenLike(t *testing.T) {
	for _, name := range []string{"username", "email", "role", "title", "page"} {
		ent, p := newParam(name)
		ClassifyParam(ent, p)
		if p.TokenLike {
			t.Errorf("expected %q NOT to be TokenLike", name)
		}
	}
}

// -------------------------------------------------------
// DebugLike classification
// -------------------------------------------------------

func TestClassifyParam_DebugLike(t *testing.T) {
	for _, name := range []string{"debug", "debug_mode", "test_flag", "dev_mode", "preview"} {
		ent, p := newParam(name)
		ClassifyParam(ent, p)
		if !p.DebugLike {
			t.Errorf("expected %q to be DebugLike", name)
		}
	}
}

func TestClassifyParam_NotDebugLike(t *testing.T) {
	for _, name := range []string{"id", "name", "page", "limit", "role"} {
		ent, p := newParam(name)
		ClassifyParam(ent, p)
		if p.DebugLike {
			t.Errorf("expected %q NOT to be DebugLike", name)
		}
	}
}

// -------------------------------------------------------
// Signal tagging
// -------------------------------------------------------

func TestClassifyParam_IDLikeSetsSignal(t *testing.T) {
	ent, p := newParam("user_id")
	ClassifyParam(ent, p)
	if !ent.SeenSignal(knowledge.SigIDLikeParam) {
		t.Error("expected SigIDLikeParam to be tagged on entity")
	}
}

func TestClassifyParam_TokenLikeSetsSignal(t *testing.T) {
	ent, p := newParam("auth_token")
	ClassifyParam(ent, p)
	if !ent.SeenSignal(knowledge.SigTokenLike) {
		t.Error("expected SigTokenLike to be tagged on entity")
	}
}

func TestClassifyParam_DebugLikeSetsSignal(t *testing.T) {
	ent, p := newParam("debug_mode")
	ClassifyParam(ent, p)
	if !ent.SeenSignal(knowledge.SigDebugFlag) {
		t.Error("expected SigDebugFlag to be tagged on entity")
	}
}

// -------------------------------------------------------
// Multiple classifications
// -------------------------------------------------------

func TestClassifyParam_MultipleClassificationsApplied(t *testing.T) {
	// "auth_user_id" contains "auth" (token) and "id" suffix (id-like)
	ent, p := newParam("auth_user_id")
	ClassifyParam(ent, p)
	if !p.IDLike {
		t.Error("expected auth_user_id to be IDLike")
	}
	if !p.TokenLike {
		t.Error("expected auth_user_id to be TokenLike")
	}
}

// -------------------------------------------------------
// No classification
// -------------------------------------------------------

func TestClassifyParam_UnclassifiedParam(t *testing.T) {
	ent, p := newParam("title")
	ClassifyParam(ent, p)
	if p.IDLike || p.TokenLike || p.DebugLike {
		t.Error("expected 'title' to have no classification")
	}
}
