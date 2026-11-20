package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplicationActivationAndRollbackPreserveVerifiedVersions(t *testing.T) {
	p, err := profile("profiles/oh2p-1.62.2.json")
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	store := filepath.Join(base, "store")
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(base, "trusted.pub")
	write(t, pubPath, []byte(base64.StdEncoding.EncodeToString(pub)))
	makeRelease := func(version string) string {
		root := filepath.Join(base, version)
		components := map[string]Component{}
		for _, name := range []string{"agent", "console", "wiki", "abilities"} {
			entry := name + "/entry"
			write(t, filepath.Join(root, filepath.FromSlash(entry)), []byte(version+name))
			components[name] = Component{Version: version, Path: entry}
		}
		spec := filepath.Join(base, version+".json")
		jsonFile(t, spec, Release{Schema: 1, Version: version, Profile: p.ID, Target: p.Target, Components: components})
		if err := sealRelease(root, spec, strings.NewReader(base64.StdEncoding.EncodeToString(key)), p); err != nil {
			t.Fatal(err)
		}
		return root
	}
	firstPath, secondPath := makeRelease("first"), makeRelease("second")
	first, err := stageApp(firstPath, pubPath, store, p)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := stageApp(firstPath, pubPath, store, p)
	if err != nil || repeated != first {
		t.Fatal("repeat staging should return the same verified version")
	}
	second, err := stageApp(secondPath, pubPath, store, p)
	if err != nil || first == second {
		t.Fatal("second signed version should stage separately")
	}
	for _, id := range []string{first, second} {
		if _, err := selectApp(store, id, pubPath, p, "activate-app"); err != nil {
			t.Fatal(err)
		}
	}
	if state, err := selectApp(store, "", pubPath, p, "rollback-app"); err != nil || state.Current != first || state.Previous != second {
		t.Fatalf("rollback failed: %+v %v", state, err)
	}
	if err := os.WriteFile(filepath.Join(store, "versions", second, "console", "entry"), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := selectApp(store, second, pubPath, p, "activate-app"); err == nil {
		t.Fatal("tampered staged version activated")
	}
	if state, err := selectApp(store, "", pubPath, p, "resolve-app"); err != nil || state.Current != first {
		t.Fatalf("valid active version was lost: %+v %v", state, err)
	}
}
