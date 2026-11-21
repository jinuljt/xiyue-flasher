package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

var adminSetupPage = template.Must(template.New("admin-setup").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>喜悦安装 · 设置管理员</title><style>
body{font:16px/1.6 system-ui,sans-serif;background:#f3f6f2;color:#1a3028;margin:0}
main{max-width:480px;margin:32px auto;background:white;padding:24px;border:1px solid #cfdbd3;border-radius:14px}
label{display:block;margin:14px 0} input,button{font:inherit;padding:8px;box-sizing:border-box}
input:not([type=hidden]){display:block;width:100%;border:1px solid #7a9185;border-radius:6px}
button{background:#245540;color:white;border:0;border-radius:6px}
[role=alert]{color:#94332d}
.password-strength{display:flex;align-items:center;gap:9px;font-size:.85em;margin:4px 0 14px}
.password-strength[hidden]{display:none}.strength-bar{width:72px;height:5px;border-radius:4px}
.password-strength[data-level=weak]{color:#9a302b}.password-strength[data-level=weak] .strength-bar{background:linear-gradient(to right,#b94038 33%,#dfe5df 33%)}
.password-strength[data-level=medium]{color:#805715}.password-strength[data-level=medium] .strength-bar{background:linear-gradient(to right,#b98121 66%,#dfe5df 66%)}
.password-strength[data-level=strong]{color:#235e40}.password-strength[data-level=strong] .strength-bar{background:#337f55}

</style></head><body><main>
<h1>{{if .Done}}安装完成{{else}}设置管理员{{end}}</h1>
{{if .Done}}<p>使用刚设置的用户名和密码登录喜悦。</p><p><a href="{{.Console}}">打开喜悦控制台</a></p>
{{else}}<p>为这台音箱设置控制台的登录账号。</p>
<form method="post" action="/">
<input type="hidden" name="form_token" value="{{.Token}}">
<label>用户名<input name="username" required autocomplete="username" maxlength="64"></label>
<label>密码<input id="install-password" name="password" type="password" required autocomplete="new-password" maxlength="256"></label>
<p id="password-strength" class="password-strength" role="status" hidden><span class="strength-bar" aria-hidden="true"></span><span class="strength-label"></span></p>
<label>确认密码<input name="confirmation" type="password" required autocomplete="new-password" maxlength="256"></label>
{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}
<button type="submit">保存并完成安装</button></form>{{end}}
</main>{{if not .Done}}<script src="/password-strength.js" defer></script>{{end}}</body></html>`))

const installerStrengthJS = `
function updatePasswordStrength(input, meter) {
  const password = input.value;
  meter.hidden = password === '';
  if (meter.hidden) return;
  const length = [...password].length;
  const variety = new Set(password).size;
  const groups = [/[a-z]/, /[A-Z]/, /\d/, /[^a-zA-Z\d\s]/].filter(test => test.test(password)).length;
  const common = /^(?:password|qwerty|admin|abc123|123456)(?:\d|!)*$/i.test(password);
  let level = 'weak';
  if (!common && length >= 8 && variety >= 5) {
    level = length >= 12 && variety >= 8 && (groups >= 3 || length >= 16) ? 'strong' : 'medium';
  }
  meter.dataset.level = level;
  meter.querySelector('.strength-label').textContent = {
    weak: '弱 · 建议换一个更难猜的密码', medium: '中', strong: '强'
  }[level];
}

const input = document.getElementById('install-password');
const meter = document.getElementById('password-strength');
input.addEventListener('input', () => updatePasswordStrength(input, meter));
updatePasswordStrength(input, meter);
`

func adminSetupHandler(host, console, token string, provision func(context.Context, string, string) error) http.Handler {
	var mu sync.Mutex
	var done bool
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		if r.Host != host {
			http.Error(w, "invalid installer host", 403)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/password-strength.js" {
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
			_, _ = w.Write([]byte(installerStrengthJS))
			return
		}
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		var issue string
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodGet:
		case http.MethodPost:
			r.Body = http.MaxBytesReader(w, r.Body, 8192)
			if r.Header.Get("Origin") != "http://"+host || r.ParseForm() != nil ||
				subtle.ConstantTimeCompare([]byte(r.PostForm.Get("form_token")), []byte(token)) != 1 {
				http.Error(w, "invalid installer request", 403)
				return
			}
			if !done {
				username := strings.TrimSpace(r.PostForm.Get("username"))
				password := r.PostForm.Get("password")
				switch {
				case username == "" || len(username) > 64 || password == "" || len(password) > 256:
					issue = "请填写有效的用户名和密码。"
				case password != r.PostForm.Get("confirmation"):
					issue = "两次输入的密码不一致。"
				default:
					if err := provision(r.Context(), username, password); err != nil {
						issue = "音箱未确认设置。请检查安装连接，或用刚设置的账号登录控制台。"
					} else {
						done = true
					}
				}
			}
		default:
			w.Header().Set("Allow", "GET, POST")
			w.WriteHeader(405)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = adminSetupPage.Execute(w, struct {
			Done                  bool
			Console, Token, Error string
		}{done, console, token, issue})
	})
}

func runAdminSetup(console string, command []string) error {
	target, err := url.Parse(console)
	if err != nil || target.Scheme != "https" || target.Hostname() == "" || target.User != nil ||
		target.Path != "/" && target.Path != "" || target.RawQuery != "" || target.Fragment != "" || len(command) == 0 {
		return errors.New("用法：setup-admin https://音箱地址:端口/ -- 安装传输命令")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	host := listener.Addr().String()
	address := "http://" + host + "/"
	provision := func(parent context.Context, username, password string) error {
		ctx, cancel := context.WithTimeout(parent, 20*time.Second)
		defer cancel()
		raw, err := json.Marshal(map[string]string{"username": username, "password": password})
		if err != nil {
			return err
		}
		defer clear(raw)
		cmd := exec.CommandContext(ctx, command[0], command[1:]...)
		cmd.Stdin = bytes.NewReader(raw)
		return cmd.Run()
	}
	server := &http.Server{Handler: adminSetupHandler(host, console, rand.Text(), provision),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 25 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	fmt.Println("喜悦管理员安装页：" + address)
	if runtime.GOOS == "windows" {
		_ = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", address).Start()
	}
	return server.Serve(listener)
}
