package testutil

import (
	"bytes"
	"io"
	"net/http"
)

// MockResp builds a minimal *http.Response suitable for use in engine tests.
// The body is set as a ReadCloser wrapping the provided bytes.
// Pass nil body for responses where body content doesn't matter (redirects, etc).
func MockResp(status int, contentType string, body []byte) *http.Response {
	h := http.Header{}
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	var rc io.ReadCloser
	if body != nil {
		rc = io.NopCloser(bytes.NewReader(body))
	} else {
		rc = io.NopCloser(bytes.NewReader(nil))
	}
	return &http.Response{
		StatusCode: status,
		Header:     h,
		Body:       rc,
	}
}

// MockRespWithHeader builds a MockResp and sets an additional header.
// Useful for redirect tests that need a Location header.
func MockRespWithHeader(status int, contentType, headerKey, headerVal string, body []byte) *http.Response {
	resp := MockResp(status, contentType, body)
	resp.Header.Set(headerKey, headerVal)
	return resp
}

// JSON fixtures — reusable bodies for common test scenarios

// UserJSON is a single user object response.
var UserJSON = []byte(`{"id":1,"username":"alice","email":"alice@example.com","role":"member"}`)

// UsersJSON is a list of users.
var UsersJSON = []byte(`[{"id":1,"username":"alice"},{"id":2,"username":"bob"}]`)

// PostJSON is a single post object response.
var PostJSON = []byte(`{"id":1,"title":"First Post","body":"Content here","owner_id":1}`)

// ErrorJSON is a typical error envelope — keys should never be registered as params.
var ErrorJSON = []byte(`{"error":"not found","message":"resource does not exist","status":404}`)

// ForbiddenJSON is a 403 error envelope.
var ForbiddenJSON = []byte(`{"error":"forbidden","detail":"insufficient permissions"}`)

// HTML fixtures

// LoginHTML is a minimal login form page.
var LoginHTML = []byte(`<!doctype html>
<html>
<body>
<form method="POST" action="/login/submit">
  <input name="username" type="text">
  <input name="password" type="password">
  <button type="submit">Login</button>
</form>
</body>
</html>`)

// HomeHTML is a page with navigation links.
var HomeHTML = []byte(`<!doctype html>
<html>
<body>
  <a href="/api/users">Users</a>
  <a href="/api/posts">Posts</a>
  <a href="/admin">Admin</a>
</body>
</html>`)
