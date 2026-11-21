// xiyue-flasher performs offline checks only. It never opens a device transport.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

type Profile struct {
	ID           string   `json:"id"`
	Model        string   `json:"model"`
	Firmware     string   `json:"firmware"`
	Target       string   `json:"userspace_target"`
	Status       string   `json:"status"`
	Flash        bool     `json:"flash_implemented"`
	Requirements []string `json:"requirements"`
}
type Identity struct {
	Model    string `json:"model"`
	Firmware string `json:"firmware"`
	Target   string `json:"userspace_target"`
	Source   string `json:"source"`
}
type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type Component struct {
	Version string `json:"version"`
	Path    string `json:"path"`
}
type Release struct {
	Schema     int                  `json:"schema"`
	Version    string               `json:"version"`
	Profile    string               `json:"profile"`
	Target     string               `json:"userspace_target"`
	Components map[string]Component `json:"components"`
	Files      []File               `json:"files"`
}
type Snapshot struct {
	Schema  int    `json:"schema"`
	Profile string `json:"profile"`
	Scope   string `json:"scope"`
	Files   []File `json:"files"`
}

func decode(data []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("expected one JSON document")
	}
	return nil
}
func readJSON(name string, v any) error {
	data, err := os.ReadFile(name)
	if err != nil {
		return err
	}
	return decode(data, v)
}
func profile(name string) (Profile, error) {
	var p Profile
	if err := readJSON(name, &p); err != nil {
		return p, err
	}
	// Only this reference contract is supported; a supplied profile cannot widen it.
	if p.ID != "oh2p-1.62.2" || p.Model != "OH2P" || p.Firmware != "1.62.2" || p.Target != "armv7-linux-gnueabihf" || p.Status != "reference-only-not-a-detection-result" || p.Flash {
		return p, errors.New("unsupported or unsafe profile")
	}
	required := []string{"read_actual_device_identity", "match_firmware_and_model", "verify_release_image_checksum_and_origin", "backup_and_verify_before_write", "explicit_flash_confirmation", "readback_verification", "documented_recovery_path"}
	if len(p.Requirements) != len(required) {
		return p, errors.New("incomplete profile requirements")
	}
	for i, r := range required {
		if p.Requirements[i] != r {
			return p, errors.New("profile requirements differ from reference")
		}
	}
	return p, nil
}
func match(p Profile, i Identity) error {
	if i.Source != "manual" && i.Source != "fixture" {
		return errors.New("identity source must be manual or fixture; USB detection is not implemented")
	}
	if i.Model != p.Model || i.Firmware != p.Firmware || i.Target != p.Target {
		return errors.New("identity does not match reference profile")
	}
	return nil
}
func safePath(p string) bool {
	if p == "" || p == "." || path.Clean(p) != p || path.IsAbs(p) || strings.ContainsAny(p, "\\:\x00") {
		return false
	}
	for _, r := range p {
		if r < 32 {
			return false
		}
	}
	for _, s := range strings.Split(p, "/") {
		if s == ".." || strings.HasSuffix(s, ".") || strings.HasSuffix(s, " ") || strings.ContainsAny(s, "<>\"|?*") {
			return false
		}
		stem := strings.ToUpper(strings.SplitN(s, ".", 2)[0])
		if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || (len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) && stem[3] >= '0' && stem[3] <= '9') {
			return false
		}
	}
	return true
}
func digest(name string) (File, error) {
	var out File
	f, err := os.Open(name)
	if err != nil {
		return out, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return out, err
	}
	if !st.Mode().IsRegular() {
		return out, errors.New("not a regular file")
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return out, err
	}
	return File{Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}
func inventory(root string, excluded map[string]bool) ([]File, error) {
	st, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("root must be a real directory")
	}
	var files []File
	seen := map[string]bool{}
	err = filepath.WalkDir(root, func(name string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == root {
			return nil
		}
		rel, e := filepath.Rel(root, name)
		if e != nil {
			return e
		}
		rel = filepath.ToSlash(rel)
		if !safePath(rel) {
			return fmt.Errorf("unsafe path: %s", rel)
		}
		lower := strings.ToLower(rel)
		if seen[lower] {
			return errors.New("case-insensitive path collision")
		}
		seen[lower] = true
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("symlinks are not allowed")
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return errors.New("special files are not allowed")
		}
		if excluded[rel] {
			return nil
		}
		f, e := digest(name)
		if e != nil {
			return e
		}
		f.Path = rel
		files = append(files, f)
		return nil
	})
	return files, err
}
func compare(root string, expected []File, excluded map[string]bool) error {
	if len(expected) == 0 {
		return errors.New("empty file inventory")
	}
	want := map[string]File{}
	lower := map[string]bool{}
	for _, f := range expected {
		b, e := hex.DecodeString(f.SHA256)
		if !safePath(f.Path) || excluded[f.Path] || f.Size < 0 || e != nil || len(b) != 32 || f.SHA256 != strings.ToLower(f.SHA256) || lower[strings.ToLower(f.Path)] {
			return errors.New("invalid or duplicate inventory entry")
		}
		want[f.Path] = f
		lower[strings.ToLower(f.Path)] = true
	}
	actual, err := inventory(root, excluded)
	if err != nil {
		return err
	}
	if len(actual) != len(want) {
		return errors.New("file inventory count differs")
	}
	for _, a := range actual {
		if w, ok := want[a.Path]; !ok || w != a {
			return fmt.Errorf("file mismatch: %s", a.Path)
		}
	}
	return nil
}

const (
	maxManifestBytes = 1 << 20
	maxKeyBytes      = 4 << 10
)

func readReleaseMetadata(name string, limit int64) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(data)) > limit {
		return nil, errors.New("release metadata exceeds its size limit")
	}
	return data, err
}

func verifyRelease(root, keyPath string, p Profile) (Release, error) {
	var r Release
	// Trust comes from the caller's independently obtained key, never the package.
	keyText, err := readReleaseMetadata(keyPath, maxKeyBytes)
	if err != nil {
		return r, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyText)))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return r, errors.New("invalid trusted Ed25519 public key")
	}
	data, err := readReleaseMetadata(filepath.Join(root, "release.json"), maxManifestBytes)
	if err != nil {
		return r, err
	}
	sigText, err := readReleaseMetadata(filepath.Join(root, "release.sig"), maxKeyBytes)
	if err != nil {
		return r, err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigText)))
	if err != nil || !ed25519.Verify(key, data, sig) {
		return r, errors.New("release signature verification failed")
	}
	if err = decode(data, &r); err != nil {
		return r, err
	}
	if err = validateRelease(r, p); err != nil {
		return r, err
	}
	return r, compare(root, r.Files, map[string]bool{"release.json": true, "release.sig": true})
}
func validateRelease(r Release, p Profile) error {
	if r.Schema != 1 || strings.TrimSpace(r.Version) == "" || r.Profile != p.ID || r.Target != p.Target {
		return errors.New("release is incompatible with profile")
	}
	if len(r.Components) != 4 {
		return errors.New("release must pin agent, console, wiki and abilities")
	}
	for _, name := range []string{"agent", "console", "wiki", "abilities"} {
		c, ok := r.Components[name]
		if !ok || strings.TrimSpace(c.Version) == "" || !safePath(c.Path) {
			return fmt.Errorf("missing component: %s", name)
		}
		found := false
		for _, f := range r.Files {
			if f.Path == c.Path {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("component entry is absent from inventory: %s", name)
		}
	}
	return nil
}

// sealRelease signs exact manifest bytes using a key supplied through stdin only.
// The staging directory must contain public release assets, never runtime data.
func sealRelease(root, spec string, keyInput io.Reader, p Profile) error {
	var r Release
	if err := readJSON(spec, &r); err != nil {
		return err
	}
	if len(r.Files) != 0 {
		return errors.New("spec files must be empty; inventory is generated from staging")
	}
	files, err := inventory(root, nil)
	if err != nil {
		return err
	}
	for _, f := range files {
		if strings.EqualFold(f.Path, "release.json") || strings.EqualFold(f.Path, "release.sig") {
			return errors.New("staging already contains release metadata")
		}
	}
	r.Files = files
	keyText, err := io.ReadAll(io.LimitReader(keyInput, 4097))
	if err != nil {
		return err
	}
	if len(keyText) > 4096 {
		return errors.New("signing input too large")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyText)))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("stdin must contain a base64 Ed25519 private key (64 bytes)")
	}
	// Reject malformed private keys with inconsistent public halves.
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	if !bytes.Equal(derived, key) {
		return errors.New("inconsistent Ed25519 private key")
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(key, data)) + "\n"
	// Validate the contract before writing either metadata file.
	if err = validateRelease(r, p); err != nil {
		return err
	}
	for name, body := range map[string][]byte{"release.json": data, "release.sig": []byte(sig)} {
		f, e := os.OpenFile(filepath.Join(root, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if e != nil {
			return e
		}
		_, e = f.Write(body)
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func backup(source, dest string, p Profile) error {
	files, err := inventory(source, nil)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return errors.New("source is empty")
	}
	for _, f := range files {
		if strings.EqualFold(f.Path, "snapshot.json") {
			return errors.New("source uses reserved snapshot.json path")
		}
	}
	src, err := filepath.EvalSymlinks(source)
	if err != nil {
		return err
	}
	src, err = filepath.Abs(src)
	if err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(dest))
	if err != nil {
		return err
	}
	dst, err := filepath.Abs(filepath.Join(parent, filepath.Base(dest)))
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(src, dst)
	if err != nil {
		return err
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return errors.New("backup destination must be outside source")
	}
	if err = os.Mkdir(dest, 0700); err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(dest)
		}
	}()
	for _, f := range files {
		to := filepath.Join(dest, filepath.FromSlash(f.Path))
		if err = os.MkdirAll(filepath.Dir(to), 0700); err != nil {
			return err
		}
		// Copy only regular files from the previously checked source directory.
		in, e := os.Open(filepath.Join(source, filepath.FromSlash(f.Path)))
		if e != nil {
			return e
		}
		out, e := os.OpenFile(to, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			in.Close()
			return e
		}
		_, e = io.Copy(out, in)
		in.Close()
		closeErr := out.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
	}
	data, err := json.MarshalIndent(Snapshot{Schema: 1, Profile: p.ID, Scope: "application-files-only", Files: files}, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dest, "snapshot.json"), append(data, '\n'), 0600); err != nil {
		return err
	}
	if err = verifyBackup(dest, "", p); err != nil {
		return err
	}
	complete = true
	return nil
}
func verifyBackup(root, restored string, p Profile) error {
	var s Snapshot
	if err := readJSON(filepath.Join(root, "snapshot.json"), &s); err != nil {
		return err
	}
	if s.Schema != 1 || s.Profile != p.ID || s.Scope != "application-files-only" {
		return errors.New("unsupported backup scope or profile")
	}
	if err := compare(root, s.Files, map[string]bool{"snapshot.json": true}); err != nil {
		return err
	}
	if restored != "" {
		return compare(restored, s.Files, nil)
	}
	return nil
}
func run(args []string) (map[string]any, error) {
	if len(args) == 0 {
		return nil, errors.New("use profile, seal-release, preflight, backup, verify-backup, check-restore, stage-app, activate-app, rollback-app, resolve-app, or wizard")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	profilePath := flags.String("profile", "profiles/oh2p-1.62.2.json", "reference profile")
	identity := flags.String("identity", "", "manual/fixture identity JSON")
	release := flags.String("release", "", "release directory")
	key := flags.String("trusted-key", "", "independently trusted base64 Ed25519 public key")
	spec := flags.String("spec", "", "release metadata JSON outside staging")
	source := flags.String("source", "", "application files source")
	backupPath := flags.String("backup", "", "backup directory")
	restored := flags.String("restored", "", "already restored application directory (read only)")
	appStore := flags.String("app-store", "", "application-only release storage directory")
	appVersion := flags.String("app-version", "", "staged release ID")
	if err := flags.Parse(args[1:]); err != nil {
		return nil, err
	}
	if flags.NArg() != 0 {
		return nil, errors.New("unexpected arguments")
	}
	p, err := profile(*profilePath)
	if err != nil {
		return nil, err
	}
	result := map[string]any{"ok": true, "command": args[0], "profile": p.ID, "flash_allowed": false, "hardware_verified": false, "usb_detection": false}
	switch args[0] {
	case "profile":
		result["status"] = p.Status
	case "seal-release":
		if *release == "" || *spec == "" {
			return nil, errors.New("seal-release requires release and spec; signing key is read from stdin")
		}
		err = sealRelease(*release, *spec, os.Stdin, p)
		result["status"] = "release-manifest-signed"
	case "preflight":
		if *identity == "" || *release == "" || *key == "" || *backupPath == "" {
			return nil, errors.New("preflight requires identity, release, trusted-key and backup")
		}
		var i Identity
		if err = readJSON(*identity, &i); err != nil {
			return nil, err
		}
		if err = match(p, i); err != nil {
			return nil, err
		}
		r, e := verifyRelease(*release, *key, p)
		if e != nil {
			return nil, e
		}
		if err = verifyBackup(*backupPath, "", p); err != nil {
			return nil, err
		}
		result["identity_source"] = i.Source
		result["release_version"] = r.Version
		result["status"] = "offline-inputs-verified"
		result["pending_gates"] = []string{"actual-device-identity", "power-cable-driver-check", "explicit-flash-confirmation", "hardware-install-and-readback", "hardware-recovery-drill", "agent-pairing-and-runtime"}
	case "stage-app":
		if *appStore == "" || *release == "" || *key == "" {
			return nil, errors.New("stage-app requires app-store, release and trusted-key")
		}
		id, e := stageApp(*release, *key, *appStore, p)
		if e != nil {
			return nil, e
		}
		result["app_version"] = id
	case "activate-app", "rollback-app", "resolve-app":
		if *appStore == "" || *key == "" {
			return nil, errors.New("application selection requires app-store and trusted-key")
		}
		state, e := selectApp(*appStore, *appVersion, *key, p, args[0])
		if e != nil {
			return nil, e
		}
		result["active_version"] = state.Current
		result["previous_version"] = state.Previous
		result["application_directory"] = filepath.Join(*appStore, "versions", state.Current)
	case "backup":
		if *source == "" || *backupPath == "" {
			return nil, errors.New("backup requires source and backup")
		}
		err = backup(*source, *backupPath, p)
		result["scope"] = "application-files-only"
	case "verify-backup":
		if *backupPath == "" {
			return nil, errors.New("verify-backup requires backup")
		}
		err = verifyBackup(*backupPath, "", p)
	case "check-restore":
		if *backupPath == "" || *restored == "" {
			return nil, errors.New("check-restore requires backup and restored")
		}
		err = verifyBackup(*backupPath, *restored, p)
		result["status"] = "application-files-match"
		result["hardware_recovery_verified"] = false
	default:
		return nil, errors.New("unknown command")
	}
	return result, err
}
func main() {
	if len(os.Args) >= 2 && os.Args[1] == "setup-admin" {
		if len(os.Args) < 5 || os.Args[3] != "--" {
			fmt.Fprintln(os.Stderr, "用法：setup-admin https://音箱地址:端口/ -- 安装传输命令")
			os.Exit(1)
		}
		if err := runAdminSetup(os.Args[2], os.Args[4:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "wizard" {
		if err := runWizard(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	result, err := run(os.Args[1:])
	if err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": false, "error": err.Error(), "flash_allowed": false, "hardware_verified": false})
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
}
