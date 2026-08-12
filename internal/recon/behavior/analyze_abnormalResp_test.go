package behavior

import (
	"bytes"
	"testing"
)

// -------------------------------------------------------
// analyzeAbnormalResponses
// -------------------------------------------------------

func TestAnalyzeAbnormalResponses_LargerDifferentResponseRecorded(t *testing.T) {
	e := testEngine()

	targetURL := "http://example.com/api/users"
	target := e.k.Entity(targetURL)

	e.identities = []Identity{
		{Name: "anonymous"},
		{Name: "session"},
	}

	referenceBody := []byte(`{"error":"unauthorized"}`)
	candidateBody := bytes.Repeat([]byte("A"), 12*1024)

	referenceFP := fpString(401, referenceBody)
	candidateFP := fpString(200, candidateBody)

	reference := probeReference{
		Identity:    "anonymous",
		Fingerprint: referenceFP,
		Evidence: probeResponseEvidence{
			URL:         targetURL,
			Method:      "GET",
			Body:        referenceBody,
			ContentType: "application/json",
			Status:      401,
		},
	}

	evidence := map[string]probeResponseEvidence{
		"anonymous": reference.Evidence,
		"session": {
			URL:         targetURL,
			Method:      "GET",
			Body:        candidateBody,
			ContentType: "application/json",
			Status:      200,
		},
	}

	probeFP := map[string]string{
		"anonymous": referenceFP,
		"session":   candidateFP,
	}

	e.analyzeAbnormalResponses(
		target,
		probeFP,
		evidence,
		reference,
		true,
	)

	if len(target.AbnormalResponses) != 1 {
		t.Fatalf(
			"expected 1 abnormal response, got %d",
			len(target.AbnormalResponses),
		)
	}

	got := target.AbnormalResponses[0]

	if got.URL != targetURL {
		t.Errorf("expected URL %q, got %q", targetURL, got.URL)
	}

	if got.Method != "GET" {
		t.Errorf("expected method GET, got %q", got.Method)
	}

	if got.Identity != "session" {
		t.Errorf("expected identity session, got %q", got.Identity)
	}

	if got.Status != 200 {
		t.Errorf("expected status 200, got %d", got.Status)
	}

	if got.ContentType != "application/json" {
		t.Errorf(
			"expected content type application/json, got %q",
			got.ContentType,
		)
	}

	if got.BodySize != len(candidateBody) {
		t.Errorf(
			"expected body size %d, got %d",
			len(candidateBody),
			got.BodySize,
		)
	}

	if got.Fingerprint != candidateFP {
		t.Errorf(
			"expected fingerprint %q, got %q",
			candidateFP,
			got.Fingerprint,
		)
	}

	if !bytes.Equal(got.Body, candidateBody) {
		t.Error("stored abnormal body does not match candidate body")
	}

	if got.Reason == "" {
		t.Error("expected abnormal response reason")
	}
}
