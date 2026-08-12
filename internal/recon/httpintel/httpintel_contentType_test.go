package httpintel

import "testing"

func TestLearnContentType_QuotedCharsetParameter(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{"Content-Type": `application/json; charset="utf-8"`}))

	if !ent.Content.LooksLikeJSON {
		t.Error("expected LooksLikeJSON=true for application/json with quoted charset parameter")
	}
	if ent.Content.MIMEs["application/json"] != 1 {
		t.Errorf("expected MIMEs[application/json]=1, got %d", ent.Content.MIMEs["application/json"])
	}
}

func TestLearnContentType_MixedCaseNormalized(t *testing.T) {
	ent := newEnt()
	Learn(ent, resp(200, map[string]string{"Content-Type": "Application/JSON; Charset=UTF-8"}))

	if ent.Content.MIMEs["application/json"] != 1 {
		t.Errorf("expected MIMEs[application/json]=1 (lowercased), got %v", ent.Content.MIMEs)
	}
}

func TestLearnContentType_MalformedFallsBackToManualParsing(t *testing.T) {
	ent := newEnt()
	// comma-separated content types aren't valid per RFC — mime.ParseMediaType
	// rejects this outright, exercising the fallback path.
	Learn(ent, resp(200, map[string]string{"Content-Type": "application/json, application/xml"}))

	if !ent.Content.LooksLikeJSON {
		t.Error("expected LooksLikeJSON=true via fallback parsing for malformed Content-Type")
	}
}
