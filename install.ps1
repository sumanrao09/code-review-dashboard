#Requires -Version 5.1
<#
  Secure Code Review Dashboard - one-shot bare-metal installer (Windows).

  Installs everything PROJECT-LOCAL (no global system changes):
    - Python venv (.venv) + app dependencies
    - Semgrep        -> pip, into the venv
    - SCC            -> .venv\Scripts\scc.exe
    - Snyk           -> .venv\Scripts\snyk.exe
    - sonar-scanner  -> .tools\  (bundles its own JRE) + shim in .venv\Scripts

  Docker is only needed for the SonarQube *server*:
    docker compose up -d sonarqube

  Run:
    powershell -ExecutionPolicy Bypass -File .\install.ps1
#>
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"  # makes Invoke-WebRequest much faster

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$SccVersion = "3.7.0"
$SonarScannerVersion = "7.1.0.4889"
$Scripts = Join-Path $Root ".venv\Scripts"
$Tools = Join-Path $Root ".tools"

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Ok($msg) { Write-Host "    $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "    WARNING: $msg" -ForegroundColor Yellow }

# ---------- Python + venv ----------
Step "Python virtual environment"
$pyCmd =
  if (Get-Command py -ErrorAction SilentlyContinue) { "py" }
  elseif (Get-Command python -ErrorAction SilentlyContinue) { "python" }
  else { throw "Python 3.11+ not found. Install it from https://python.org first." }
if (-not (Test-Path (Join-Path $Root ".venv"))) {
  & $pyCmd -m venv (Join-Path $Root ".venv")
}
$VenvPy = Join-Path $Scripts "python.exe"
& $VenvPy -c "import sys; assert sys.version_info >= (3, 11), 'Python 3.11+ required, found ' + sys.version"
& $VenvPy -m pip install --quiet --upgrade pip
& $VenvPy -m pip install --quiet -r (Join-Path $Root "requirements.txt")
Ok "venv ready, app dependencies installed"

# ---------- Semgrep (isolated venv) ----------
# Semgrep's dependencies clash with the app's (it pins a newer starlette than
# FastAPI allows), so it gets its OWN venv; only its launcher goes on the PATH.
Step "Semgrep"
$SemgrepVenv = Join-Path $Tools "semgrep-venv"
$SemgrepExe = Join-Path $SemgrepVenv "Scripts\semgrep.exe"
try {
  if (-not (Test-Path $SemgrepExe)) {
    & $pyCmd -m venv $SemgrepVenv
    & (Join-Path $SemgrepVenv "Scripts\python.exe") -m pip install --quiet --upgrade pip
    & (Join-Path $SemgrepVenv "Scripts\python.exe") -m pip install --quiet semgrep
  }
  # pip's .exe launcher embeds the absolute path of its interpreter, so the
  # copy still runs inside the isolated venv.
  Copy-Item $SemgrepExe $Scripts -Force
  Ok "installed to .tools\semgrep-venv (isolated), launcher in .venv\Scripts"
} catch {
  Warn "semgrep install failed ($_). Semgrep will be skipped by scans."
}

# ---------- SCC (static binary) ----------
Step "SCC $SccVersion"
if (Test-Path (Join-Path $Scripts "scc.exe")) {
  Ok "already installed"
} else {
  $zip = Join-Path $env:TEMP "scc.zip"
  $extract = Join-Path $env:TEMP "scc-extract"
  Invoke-WebRequest "https://github.com/boyter/scc/releases/download/v$SccVersion/scc_Windows_x86_64.zip" -OutFile $zip
  Expand-Archive $zip -DestinationPath $extract -Force
  Copy-Item (Join-Path $extract "scc.exe") $Scripts -Force
  Remove-Item $zip -Force; Remove-Item $extract -Recurse -Force
  Ok "installed to .venv\Scripts\scc.exe"
}

# ---------- Snyk (static binary) ----------
Step "Snyk CLI"
if (Test-Path (Join-Path $Scripts "snyk.exe")) {
  Ok "already installed"
} else {
  Invoke-WebRequest "https://static.snyk.io/cli/latest/snyk-win.exe" -OutFile (Join-Path $Scripts "snyk.exe")
  Ok "installed to .venv\Scripts\snyk.exe (paste your token in Settings to enable it)"
}

# ---------- sonar-scanner (bundles its own JRE) ----------
Step "sonar-scanner $SonarScannerVersion"
$SsDir = Join-Path $Tools "sonar-scanner-$SonarScannerVersion-windows-x64"
if (-not (Test-Path $SsDir)) {
  $zip = Join-Path $env:TEMP "sonar-scanner.zip"
  Invoke-WebRequest "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-$SonarScannerVersion-windows-x64.zip" -OutFile $zip
  New-Item -ItemType Directory -Force $Tools | Out-Null
  Expand-Archive $zip -DestinationPath $Tools -Force
  Remove-Item $zip -Force
}
# Shim so `sonar-scanner` resolves whenever the venv is active
Set-Content -Path (Join-Path $Scripts "sonar-scanner.bat") `
  -Value "@echo off`r`ncall `"$SsDir\bin\sonar-scanner.bat`" %*"
Ok "installed to .tools\ with a shim in .venv\Scripts"

# ---------- Verify ----------
Step "Verifying installed tools"
$env:Path = "$Scripts;$env:Path"
# Native tools write warnings to stderr; don't let that abort the script.
$ErrorActionPreference = "Continue"
$semv = (& (Join-Path $Scripts "semgrep.exe") --version 2>&1 |
         ForEach-Object { "$_" } | Where-Object { $_ -match "^\d" } | Select-Object -First 1)
Ok ("semgrep       " + $semv)
Ok ("scc           " + ((& (Join-Path $Scripts "scc.exe") --version 2>&1) -join " "))
Ok ("snyk          " + ((& (Join-Path $Scripts "snyk.exe") --version 2>&1) -join " "))
Ok "sonar-scanner  (shim created; verified on first scan - JVM boot is slow)"
$ErrorActionPreference = "Stop"

# ---------- Docker (for the SonarQube server only) ----------
Step "Docker (optional - only needed for the SonarQube server)"
if (Get-Command docker -ErrorAction SilentlyContinue) {
  Ok "Docker found. Start SonarQube with: docker compose up -d sonarqube"
} else {
  Warn "Docker not found. SonarQube scans need it; the other tools work without it."
}

Write-Host @"

Done. Next steps:
  1. .venv\Scripts\Activate.ps1
  2. docker compose up -d sonarqube        # optional, for SonarQube scans
  3. uvicorn app.main:app --host 127.0.0.1 --port 8000
  4. Open http://localhost:8000  (paste your Snyk token in Settings -> Scanner tokens)
"@ -ForegroundColor Cyan
exit 0