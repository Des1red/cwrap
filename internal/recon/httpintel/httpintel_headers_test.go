package httpintel

import (
	"net/http"
	"testing"
)

func TestLearn_CSRFCookieNameFalsePositiveFixed(t *testing.T) {
	ent := newEnt()
	h := http.Header{}
	h.Add("Set-Cookie", "session=xsrf_debug_enabled; Path=/; HttpOnly")
	Learn(ent, &http.Response{StatusCode: 200, Header: h})

	if ent.HTTP.CSRFPresent {
		t.Error("expected CSRFPresent=false when 'xsrf' appears only in cookie value, not name")
	}
}

func TestLearn_CSRFCookieAmongMultipleCookies(t *testing.T) {
	ent := newEnt()
	h := http.Header{}
	h.Add("Set-Cookie", "session=abc123; Path=/; HttpOnly")
	h.Add("Set-Cookie", "XSRF-TOKEN=def456; Path=/")
	Learn(ent, &http.Response{StatusCode: 200, Header: h})

	if !ent.HTTP.CSRFPresent {
		t.Error("expected CSRFPresent=true when one of multiple Set-Cookie headers has a CSRF-named cookie")
	}
}
