$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$dist = Join-Path $root "dist"
$runtime = Join-Path $dist "runtime"
$source = Join-Path $root "tray-app\RmDirectTray.cs"
$compiler = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$codexNode = Join-Path $env:LOCALAPPDATA "OpenAI\Codex\runtimes\cua_node\1b23c930bdf84ed6\bin\node.exe"
$distNode = Join-Path $runtime "node.exe"
$authConfig = Join-Path $root "auth-config.json"
$distAuthConfig = Join-Path $dist "auth-config.json"
$systemNodeCommand = Get-Command node.exe -ErrorAction SilentlyContinue | Select-Object -First 1
$systemNode = if ($systemNodeCommand) { $systemNodeCommand.Source } else { $null }

if (-not (Test-Path $compiler)) {
  throw "C# compiler not found: $compiler"
}

if (-not (Test-Path $distNode) -and -not $systemNode -and -not (Test-Path $codexNode)) {
  throw "Node runtime not found. Install Node.js or place node.exe in dist\runtime."
}

New-Item -ItemType Directory -Force -Path $dist, $runtime | Out-Null

$exePath = Join-Path $dist "rm-direct.exe"

& $compiler `
  /nologo `
  /codepage:65001 `
  /target:winexe `
  /out:$exePath `
  /reference:System.dll `
  /reference:System.Drawing.dll `
  /reference:System.Windows.Forms.dll `
  $source

if ($LASTEXITCODE -ne 0) {
  throw "C# build failed with exit code $LASTEXITCODE"
}

Copy-Item -Force (Join-Path $root "server.js") (Join-Path $dist "server.js")
Copy-Item -Force (Join-Path $root "index.html") (Join-Path $dist "index.html")
Copy-Item -Force (Join-Path $root "key web.txt") (Join-Path $dist "key web.txt")
Copy-Item -Force (Join-Path $root "minus.txt") (Join-Path $dist "minus.txt")
Copy-Item -Force (Join-Path $root "kuh1.jpg") (Join-Path $dist "kuh1.jpg")
Copy-Item -Force (Join-Path $root "kuh2.jpg") (Join-Path $dist "kuh2.jpg")

if (Test-Path $authConfig) {
  Copy-Item -Force $authConfig $distAuthConfig
} elseif (Test-Path $distAuthConfig) {
  Remove-Item -Force $distAuthConfig
}

if (-not (Test-Path $distNode)) {
  $nodeSource = if ($systemNode) { $systemNode } else { $codexNode }
  Copy-Item -Force $nodeSource $distNode
}

Write-Host "Done: $exePath"

if (-not (Test-Path $authConfig)) {
  Write-Warning "auth-config.json not found. The application will stay locked until authorization is configured."
}
