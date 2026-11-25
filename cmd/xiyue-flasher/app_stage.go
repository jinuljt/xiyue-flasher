package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

var appID = regexp.MustCompile("^[a-f0-9]{64}$")

type installedApp struct {
	Current  string `json:"current"`
	Previous string `json:"previous"`
}

func stageApp(release, trustedKey, store string, p Profile) (string, error) {
	verified, err := verifyRelease(release, trustedKey, p)
	if err != nil {
		return "", err
	}
	if err = os.MkdirAll(filepath.Join(store, "versions"), 0700); err != nil {
		return "", err
	}
	versions := filepath.Join(store, "versions")
	stage, err := os.MkdirTemp(versions, ".staging-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(stage)
	src, err := os.OpenRoot(release)
	if err != nil {
		return "", err
	}
	defer src.Close()
	entries := append([]File{{Path: "release.json", Size: maxManifestBytes}, {Path: "release.sig", Size: maxKeyBytes}}, verified.Files...)
	for i, entry := range entries {
		key := entry.Path
		dest := filepath.Join(stage, filepath.FromSlash(key))
		if err = os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			return "", err
		}
		in, err := src.Open(filepath.FromSlash(key))
		if err != nil {
			return "", err
		}
		info, err := in.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > entry.Size || (i >= 2 && info.Size() != entry.Size) {
			_ = in.Close()
			return "", errors.New("release entry changed during staging")
		}
		mode := os.FileMode(0600)
		if key == verified.Components["agent"].Path {
			mode = 0700
		}
		out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			_ = in.Close()
			return "", err
		}
		_, err = io.CopyN(out, in, info.Size())
		_ = in.Close()
		if err == nil {
			err = out.Sync()
		}
		closeErr := out.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return "", err
		}
	}
	if _, err = verifyRelease(stage, trustedKey, p); err != nil {
		return "", err
	}
	manifest, err := readReleaseMetadata(filepath.Join(stage, "release.json"), maxManifestBytes)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(manifest)
	id := hex.EncodeToString(sum[:])
	dest := filepath.Join(versions, id)
	if err = os.Rename(stage, dest); err != nil {
		// Repeated staging of the same signed version is harmless.
		if _, verifyErr := verifyInstalledVersion(store, id, trustedKey, p); verifyErr != nil {
			return "", err
		}
	}
	return id, nil
}

func verifyInstalledVersion(store, id, trustedKey string, p Profile) (Release, error) {
	if !appID.MatchString(id) {
		return Release{}, errors.New("invalid application release ID")
	}
	root := filepath.Join(store, "versions", id)
	manifest, err := readReleaseMetadata(filepath.Join(root, "release.json"), maxManifestBytes)
	if err != nil {
		return Release{}, err
	}
	sum := sha256.Sum256(manifest)
	if hex.EncodeToString(sum[:]) != id {
		return Release{}, errors.New("staged release identity mismatch")
	}
	return verifyRelease(root, trustedKey, p)
}

func selectApp(store, id, trustedKey string, p Profile, operation string) (installedApp, error) {
	statePath := filepath.Join(store, "active.json")
	var state installedApp
	if err := readJSON(statePath, &state); err != nil && !os.IsNotExist(err) {
		return state, err
	}
	if operation == "rollback-app" {
		id = state.Previous
	} else if operation == "resolve-app" {
		id = state.Current
	}
	if _, err := verifyInstalledVersion(store, id, trustedKey, p); err != nil {
		return state, err
	}
	if operation == "resolve-app" || id == state.Current {
		return state, nil
	}
	state = installedApp{Current: id, Previous: state.Current}
	data, err := json.Marshal(state)
	if err != nil {
		return state, err
	}
	f, err := os.CreateTemp(store, ".active-")
	if err != nil {
		return state, err
	}
	name := f.Name()
	defer os.Remove(name)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return state, err
	}
	if err = os.Rename(name, statePath); err != nil {
		return state, err
	}
	return state, nil
}
