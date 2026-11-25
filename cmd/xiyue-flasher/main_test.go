package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func jsonFile(t *testing.T, name string, v any) {
	t.Helper()
	data, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	write(t, name, data)
}
func fixture(t *testing.T) (Profile, string, string, string, string) {
	t.Helper()
	p, e := profile("../../profiles/oh2p-1.62.2.json")
	if e != nil {
		t.Fatal(e)
	}
	base := t.TempDir()
	root := filepath.Join(base, "release")
	source := filepath.Join(base, "source")
	backupPath := filepath.Join(base, "backup")
	components := map[string]Component{}
	for _, name := range []string{"agent", "console", "wiki", "abilities"} {
		namePath := name + "/entry.txt"
		write(t, filepath.Join(root, filepath.FromSlash(namePath)), []byte("synthetic "+name))
		components[name] = Component{Version: "test-1", Path: namePath}
	}
	spec := filepath.Join(base, "spec.json")
	jsonFile(t, spec, Release{Schema: 1, Version: "test-1", Profile: p.ID, Target: p.Target, Components: components})
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	keyPath := filepath.Join(base, "trusted.pub")
	write(t, keyPath, []byte(base64.StdEncoding.EncodeToString(pub)))
	if e = sealRelease(root, spec, strings.NewReader(base64.StdEncoding.EncodeToString(priv)), p); e != nil {
		t.Fatal(e)
	}
	write(t, filepath.Join(source, "config.json"), []byte(`{"fixture":true}`))
	write(t, filepath.Join(source, "nested", "state.txt"), []byte("synthetic only"))
	if e = backup(source, backupPath, p); e != nil {
		t.Fatal(e)
	}
	return p, root, keyPath, source, backupPath
}
func TestOfflineFlow(t *testing.T) {
	p, root, key, source, b := fixture(t)
	if _, e := verifyRelease(root, key, p); e != nil {
		t.Fatal(e)
	}
	if e := verifyBackup(b, source, p); e != nil {
		t.Fatal(e)
	}
	identity := filepath.Join(t.TempDir(), "identity.json")
	jsonFile(t, identity, Identity{Model: p.Model, Firmware: p.Firmware, Target: p.Target, Source: "fixture"})
	result, e := run([]string{"preflight", "--profile", "../../profiles/oh2p-1.62.2.json", "--identity", identity, "--release", root, "--trusted-key", key, "--backup", b})
	if e != nil {
		t.Fatal(e)
	}
	if result["flash_allowed"] != false || result["hardware_verified"] != false || result["usb_detection"] != false || result["identity_source"] != "fixture" {
		t.Fatal(result)
	}
	result, e = run([]string{"check-restore", "--profile", "../../profiles/oh2p-1.62.2.json", "--backup", b, "--restored", source})
	if e != nil || result["hardware_recovery_verified"] != false {
		t.Fatal(result, e)
	}
	if e = backup(source, b, p); e == nil {
		t.Fatal("overwrote existing backup")
	}
	if e = backup(source, filepath.Join(source, "backup"), p); e == nil {
		t.Fatal("nested backup allowed")
	}
}
func TestTampering(t *testing.T) {
	for _, what := range []string{"payload", "signature", "key", "extra", "missing", "manifest", "backup", "restore", "traversal", "duplicate", "component", "firmware", "snapshot-scope"} {
		t.Run(what, func(t *testing.T) {
			p, root, key, source, b := fixture(t)
			switch what {
			case "payload":
				write(t, filepath.Join(root, "agent", "entry.txt"), []byte("modified"))
			case "signature":
				write(t, filepath.Join(root, "release.sig"), []byte("invalid"))
			case "key":
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				write(t, key, []byte(base64.StdEncoding.EncodeToString(pub)))
			case "extra":
				write(t, filepath.Join(root, "extra.txt"), []byte("extra"))
			case "missing":
				if e := os.Remove(filepath.Join(root, "wiki", "entry.txt")); e != nil {
					t.Fatal(e)
				}
			case "manifest":
				f := filepath.Join(root, "release.json")
				data, _ := os.ReadFile(f)
				write(t, f, append(data, ' '))
			case "backup":
				write(t, filepath.Join(b, "nested", "state.txt"), []byte("corrupt"))
				if e := verifyBackup(b, "", p); e == nil {
					t.Fatal("corrupt backup accepted")
				}
				return
			case "restore":
				write(t, filepath.Join(source, "extra.txt"), []byte("extra"))
				if e := verifyBackup(b, source, p); e == nil {
					t.Fatal("restore mismatch accepted")
				}
				return
			case "snapshot-scope":
				var s Snapshot
				_ = readJSON(filepath.Join(b, "snapshot.json"), &s)
				s.Scope = "partition-image"
				jsonFile(t, filepath.Join(b, "snapshot.json"), s)
				if e := verifyBackup(b, "", p); e == nil {
					t.Fatal("scope accepted")
				}
				return
			case "traversal", "duplicate":
				files, _ := inventory(source, nil)
				if what == "traversal" {
					files[0].Path = "../outside"
				} else {
					files = append(files, files[0])
				}
				if e := compare(source, files, nil); e == nil {
					t.Fatal("invalid inventory accepted")
				}
				return
			case "component", "firmware":
				var r Release
				_ = readJSON(filepath.Join(root, "release.json"), &r)
				if what == "component" {
					delete(r.Components, "wiki")
				} else {
					r.Profile = "other-firmware"
				}
				if e := validateRelease(r, p); e == nil {
					t.Fatal("incompatible contract accepted")
				}
				return
			}
			if _, e := verifyRelease(root, key, p); e == nil {
				t.Fatal("tampered release accepted")
			}
		})
	}
}
func TestTrustBoundaries(t *testing.T) {
	p, e := profile("../../profiles/oh2p-1.62.2.json")
	if e != nil {
		t.Fatal(e)
	}
	for _, i := range []Identity{{Model: "OH2P", Firmware: "1.62.2", Target: p.Target, Source: "usb"}, {Model: "other", Firmware: p.Firmware, Target: p.Target, Source: "manual"}, {Model: p.Model, Firmware: "other", Target: p.Target, Source: "fixture"}} {
		if match(p, i) == nil {
			t.Fatal("invalid identity accepted")
		}
	}
	if match(p, Identity{Model: p.Model, Firmware: p.Firmware, Target: p.Target, Source: "manual"}) != nil {
		t.Fatal("manual input rejected")
	}
	for _, s := range []string{"../escape", "/absolute", "a\\b", "C:drive", "a/../b", "CON.txt", "foo/NUL", "trailing.", "trailing ", "COM1", "a?b", "a//b", "control\x01file"} {
		if safePath(s) {
			t.Fatalf("unsafe path accepted: %s", s)
		}
	}
	bad := p
	bad.Flash = true
	file := filepath.Join(t.TempDir(), "bad.json")
	jsonFile(t, file, bad)
	if _, e = profile(file); e == nil {
		t.Fatal("unsafe profile accepted")
	}
	if decode([]byte(`{} {}`), new(Identity)) == nil || decode([]byte(`{"unknown":true}`), new(Identity)) == nil {
		t.Fatal("loose JSON parsing")
	}
	for _, args := range [][]string{nil, {"unknown"}, {"preflight"}, {"check-restore"}, {"backup"}, {"verify-backup"}, {"profile", "extra"}, {"seal-release"}} {
		if _, e = run(args); e == nil {
			t.Fatal("missing/unknown input accepted", args)
		}
	}
}
func TestSymlinksAndCaseCollision(t *testing.T) {
	base := t.TempDir()
	source := filepath.Join(base, "source")
	write(t, filepath.Join(source, "file.txt"), []byte("fixture"))
	if e := os.Symlink(filepath.Join(source, "file.txt"), filepath.Join(source, "link")); e != nil {
		t.Log("symlink creation unavailable:", e)
	} else {
		if _, e = inventory(source, nil); e == nil {
			t.Fatal("symlink accepted")
		}
		_ = os.Remove(filepath.Join(source, "link"))
	}
	write(t, filepath.Join(source, "FILE.txt"), []byte("fixture"))
	entries, e := os.ReadDir(source)
	if e != nil {
		t.Fatal(e)
	}
	if len(entries) == 2 {
		if _, e = inventory(source, nil); e == nil {
			t.Fatal("case collision accepted")
		}
	}
}

func TestSigningAndBackupFailures(t *testing.T) {
	p, root, _, source, _ := fixture(t)
	spec := filepath.Join(t.TempDir(), "spec.json")
	var r Release
	if e := readJSON(filepath.Join(root, "release.json"), &r); e != nil {
		t.Fatal(e)
	}
	r.Files = nil
	jsonFile(t, spec, r)
	if e := sealRelease(root, spec, strings.NewReader("invalid"), p); e == nil {
		t.Fatal("existing metadata accepted")
	}
	stage := t.TempDir()
	for _, c := range r.Components {
		write(t, filepath.Join(stage, c.Path), []byte("fixture"))
	}
	for _, input := range []string{"invalid", strings.Repeat("a", 4097), base64.StdEncoding.EncodeToString(make([]byte, 64))} {
		if e := sealRelease(stage, spec, strings.NewReader(input), p); e == nil {
			t.Fatal("invalid signing input accepted")
		}
	}
	empty := t.TempDir()
	if e := backup(empty, filepath.Join(t.TempDir(), "out"), p); e == nil {
		t.Fatal("empty source accepted")
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if e := os.Symlink(source, alias); e != nil {
		t.Log("directory symlink unavailable:", e)
	} else {
		if e = backup(source, filepath.Join(alias, "nested-backup"), p); e == nil {
			t.Fatal("nested backup through alias accepted")
		}
	}
	write(t, filepath.Join(source, "snapshot.JSON"), []byte("reserved"))
	if e := backup(source, filepath.Join(t.TempDir(), "out"), p); e == nil {
		t.Fatal("reserved name accepted")
	}
}
