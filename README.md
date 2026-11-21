# 喜悦 Voice · 安装预检与发布包

喜悦 Voice 是给小爱音箱用的 AI 语音助手。

Windows 可构建的离线安装前预检：OH2P 档案与手工输入核对、Ed25519 发布包验签、逐文件摘要、应用文件备份及恢复副本核对。

没有 USB 自动识别、安装向导或刷写功能。成功预检也不会允许刷写。

构建与测试：Go 1.24+，`go test ./...`；Windows PowerShell 7：`./scripts/build-windows.ps1`。

完整命令、Agent 发布接口与验收边界见 [README.html](README.html)（下载后可直接打开）。
