package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestWizardChecksOriginAndDoesNotExposeFlashActions(t *testing.T) {
	const host = "127.0.0.1:1234"
	const token = "fixture"
	calls := 0
	handler := wizardHandler(host, token, func(args []string) (map[string]any, error) {
		calls++
		if len(args) != 9 || args[0] != "preflight" || args[2] != "test.json" {
			t.Fatalf("wizard delegated unexpected command: %v", args)
		}
		return map[string]any{"release_version": "<fixture>"}, nil
	})
	form := url.Values{"token": {token}, "identity": {"test.json"}, "release": {"release"}, "key": {"public"}, "backup": {"backup"}}
	call := func(method, origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://"+host+"/", strings.NewReader(form.Encode()))
		req.Header.Set("Origin", origin)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}
	if w := call(http.MethodPost, "http://other.test"); w.Code != 403 || calls != 0 {
		t.Fatal("cross-origin request accessed local files")
	}
	if w := call(http.MethodGet, ""); w.Code != 200 || !strings.Contains(w.Body.String(), "本工具不写入音箱") {
		t.Fatal("wizard main page missing")
	}
	w := call(http.MethodPost, "http://"+host)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "离线预检通过") ||
		!strings.Contains(w.Body.String(), "&lt;fixture&gt;") || !strings.Contains(w.Body.String(), "仍需确认真实设备身份") {
		t.Fatal("wizard must render an escaped, offline-only result")
	}
}
