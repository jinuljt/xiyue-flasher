package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"
)

var wizardPage = template.Must(template.New("wizard").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>喜悦 Voice 音箱安装预检</title>
<style>
body{font:16px/1.55 system-ui,sans-serif;background:#f3f6f2;color:#1a3028;margin:0}
main{max-width:620px;margin:32px auto;background:white;padding:24px;border:1px solid #cfdbd3;border-radius:14px}
label{display:block;margin-top:14px} input,button{font:inherit;padding:8px;box-sizing:border-box}
input:not([type=hidden]){display:block;width:100%;border:1px solid #7a9185;border-radius:6px}
button{margin-top:16px;background:#245540;color:white;border:0;border-radius:6px}
.success,.error{padding:10px;border:1px solid;border-radius:6px}.success{color:#245540}.error{color:#94332d}
</style></head><body><main>
<h1>喜悦 Voice 音箱安装预检</h1>
<p>检查 OH2P 参考档案、签名应用包和应用文件备份。本工具不写入音箱。</p>
<form action="/" method="post">
<input type="hidden" name="token" value="{{.Token}}">
<label>设备资料 JSON 路径<input name="identity" required value="{{.Identity}}"></label>
<label>解压后的签名应用包目录<input name="release" required value="{{.Release}}"></label>
<label>可信公开验签密钥文件<input name="key" required value="{{.Key}}"></label>
<label>待校验的应用备份目录<input name="backup" required value="{{.Backup}}"></label>
<button type="submit">校验应用包和备份</button>
</form>
{{if .Error}}<p class="error" role="alert">未通过。{{.Error}}</p>{{end}}
{{if .Verified}}<p class="success" role="status">离线预检通过。仍需确认真实设备身份，并完成设备安装及恢复验证。版本 {{.Version}}。</p>{{end}}
</main></body></html>`))

type wizardState struct {
	Token, Identity, Release, Key, Backup, Error, Version string
	Verified                                              bool
}

func wizardHandler(host, token string, preflight func([]string) (map[string]any, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		if r.Host != host {
			http.Error(w, "invalid wizard host", 403)
			return
		}
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		state := wizardState{Token: token}
		switch r.Method {
		case http.MethodGet:
		case http.MethodPost:
			if r.Header.Get("Origin") != "http://"+host {
				http.Error(w, "invalid origin", 403)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
			if err := r.ParseForm(); err != nil || subtle.ConstantTimeCompare([]byte(r.PostForm.Get("token")), []byte(token)) != 1 {
				http.Error(w, "invalid wizard request", 403)
				return
			}
			state.Identity, state.Release, state.Key, state.Backup = r.PostForm.Get("identity"), r.PostForm.Get("release"), r.PostForm.Get("key"), r.PostForm.Get("backup")
			result, err := preflight([]string{"preflight", "-identity", state.Identity, "-release", state.Release, "-trusted-key", state.Key, "-backup", state.Backup})
			if err != nil {
				state.Error = err.Error()
			} else {
				state.Verified = true
				state.Version, _ = result["release_version"].(string)
			}
		default:
			w.Header().Set("Allow", "GET, POST")
			w.WriteHeader(405)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = wizardPage.Execute(w, state)
	})
}

func runWizard() error {
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return errors.New("cannot initialize wizard")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	host := listener.Addr().String()
	address := "http://" + host + "/"
	fmt.Println("喜悦 Voice 安装预检：" + address)
	if runtime.GOOS == "windows" {
		if command, err := exec.LookPath("rundll32.exe"); err == nil {
			_ = exec.Command(command, "url.dll,FileProtocolHandler", address).Run()
		}
	}
	s := &http.Server{Handler: wizardHandler(host, hex.EncodeToString(bytes[:]), run),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 30 * time.Second}
	return s.Serve(listener)
}
