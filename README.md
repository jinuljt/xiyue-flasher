# 喜悦 Voice 安装预检与发布工具

面向 OH2P 的安装前检查工具。它核对型号与固件、验证签名发布包，并检查应用备份与恢复副本。图形界面提供预检。USB 自动识别和固件刷写尚未实现。通过预检只代表已验证提供的档案和文件。

## 构建和使用

需要 Go 1.24 或更新版本。

```sh
go test ./...
go build -o dist/xiyue-flasher ./cmd/xiyue-flasher
./dist/xiyue-flasher profile
./dist/xiyue-flasher wizard
```

Windows 下运行 [PowerShell 构建脚本](scripts/build-windows.ps1)，按系统生成相应架构的程序和图形预检入口。

```sh
xiyue-flasher backup --source ./application-copy --backup ./local-backup
xiyue-flasher verify-backup --backup ./local-backup
xiyue-flasher preflight --identity ./identity.json --release ./release-stage --trusted-key ./publisher.pub --backup ./local-backup
xiyue-flasher check-restore --backup ./local-backup --restored ./restored-application-copy
```

## 发布包与应用更新

签名包包含 Agent、控制台、能力规范、`release.json` 和 `release.sig`。签名使用 Ed25519，校验包括设备目标档案、组件路径和逐文件摘要。发布方使用 `seal-release` 签发，签名密钥经标准输入注入。应用槽位由 `stage-app`、`activate-app`、`rollback-app` 和 `resolve-app` 管理。

| 路径 | 内容 |
| --- | --- |
| [`cmd/xiyue-flasher/`](cmd/xiyue-flasher/) | 命令行、图形预检和测试 |
| [`profiles/`](profiles/) | 设备与固件档案 |
| [`scripts/`](scripts/) | Windows 构建与启动脚本 |
| [`examples/`](examples/) | 合成档案和发布包示例 |
