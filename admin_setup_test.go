package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAdminSetupAcceptsLocalFormAndDoesNotEchoPassword(t *testing.T) {
	const host = "127.0.0.1:8477"
	const console = "https://speaker.test/"
	const formToken = "synthetic-form-token"
	const password = "x"
	var calls int
	handler := adminSetupHandler(host, console, formToken, func(_ context.Context, name, secret string) error {
		calls++
		if name != "owner" || secret != password {
			t.Fatal("wrong install credentials")
		}
		return nil
	})
	send := func(origin, confirm string) *httptest.ResponseRecorder {
		body := url.Values{"form_token": {formToken}, "username": {"owner"}, "password": {password}, "confirmation": {confirm}}
		r := httptest.NewRequest("POST", "http://"+host+"/", strings.NewReader(body.Encode()))
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := send("https://other.test", password); w.Code != http.StatusForbidden {
		t.Fatal("foreign origin could submit account setup")
	}
	if w := send("http://"+host, "mismatched"); !strings.Contains(w.Body.String(), "不一致") || calls != 0 {
		t.Fatal("mismatched passwords were accepted")
	}
	for i := 0; i < 2; i++ {
		w := send("http://"+host, password)
		if !strings.Contains(w.Body.String(), console) || strings.Contains(w.Body.String(), `value="x"`) {
			t.Fatal("installer didn't render a safe success page")
		}
	}
	r := httptest.NewRequest("GET", "http://"+host+"/password-strength.js", nil)
	script := httptest.NewRecorder()
	handler.ServeHTTP(script, r)
	if script.Code != http.StatusOK || !strings.Contains(script.Body.String(), "strength-label") {
		t.Fatal("password strength script is unavailable")
	}
	if calls != 1 {
		t.Fatalf("credentials were saved %d times", calls)
	}
}
