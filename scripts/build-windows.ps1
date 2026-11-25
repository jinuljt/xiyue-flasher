$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '..')
$previousGOOS = $env:GOOS
$previousGOARCH = $env:GOARCH
$previousCGO = $env:CGO_ENABLED
try {
    # Run on the native host before selecting the executable's target.
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
    go test ./...
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
    go vet ./...
    if ($LASTEXITCODE -ne 0) { throw 'Vet failed' }
    $env:GOOS = 'windows'
    $env:CGO_ENABLED = '0'
    foreach ($arch in @('amd64', 'arm64')) {
        $env:GOARCH = $arch
        $package = "dist/xiyue-flasher-windows-$arch"
        New-Item -ItemType Directory -Force -Path "$package/profiles" | Out-Null
        go build -trimpath -o "$package/xiyue-flasher.exe" ./cmd/xiyue-flasher
        if ($LASTEXITCODE -ne 0) { throw "Build failed: $arch" }
        Copy-Item profiles/oh2p-1.62.2.json "$package/profiles/"
        Copy-Item README.md, LICENSE, scripts/start-wizard.cmd $package
        if ($arch -eq 'amd64' -and $IsWindows -and $env:PROCESSOR_ARCHITECTURE -eq 'AMD64') {
            & "$package/xiyue-flasher.exe" profile
            if ($LASTEXITCODE -ne 0) { throw 'Windows executable smoke test failed' }
        }
        Compress-Archive -Path "$package/*" -DestinationPath "$package.zip" -Force
        $hash = (Get-FileHash "$package.zip" -Algorithm SHA256).Hash.ToLowerInvariant()
        [IO.File]::WriteAllText((Join-Path (Get-Location) "$package.zip.sha256"), "$hash  xiyue-flasher-windows-$arch.zip`n")
    }
} finally {
    $env:GOOS = $previousGOOS
    $env:GOARCH = $previousGOARCH
    $env:CGO_ENABLED = $previousCGO
    Pop-Location
}
