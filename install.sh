#!/usr/bin/env bash
# Secure Code Review Dashboard — one-shot bare-metal installer (Linux/macOS).
#
# Installs everything PROJECT-LOCAL (no global system changes):
#   - Python venv (.venv) + app dependencies
#   - Semgrep       -> pip, into the venv
#   - SCC           -> .venv/bin/scc
#   - Snyk          -> .venv/bin/snyk
#   - sonar-scanner -> .tools/ (bundles its own JRE) + symlink in .venv/bin
#
# Docker is only needed for the SonarQube *server*: docker compose up -d sonarqube
set -euo pipefail

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    echo "This script is for Linux/macOS. On Windows run install.bat" >&2
    echo "(or: powershell -ExecutionPolicy Bypass -File .\\install.ps1)" >&2
    exit 1 ;;
esac

ROOT="$(cd "$(dirname "$0")" && pwd)"
SCC_VERSION=3.7.0
SS_VERSION=7.1.0.4889
BIN="$ROOT/.venv/bin"
TOOLS="$ROOT/.tools"

step() { printf '\n\033[36m==> %s\033[0m\n' "$1"; }
ok()   { printf '    \033[32m%s\033[0m\n' "$1"; }

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)   SCC_ASSET=scc_Linux_x86_64.tar.gz;  SNYK_BIN=snyk-linux;       SS_ARCH=linux-x64      ;;
  Linux-aarch64)  SCC_ASSET=scc_Linux_arm64.tar.gz;   SNYK_BIN=snyk-linux-arm64; SS_ARCH=linux-aarch64  ;;
  Darwin-x86_64)  SCC_ASSET=scc_Darwin_x86_64.tar.gz; SNYK_BIN=snyk-macos;       SS_ARCH=macosx-x64     ;;
  Darwin-arm64)   SCC_ASSET=scc_Darwin_arm64.tar.gz;  SNYK_BIN=snyk-macos-arm64; SS_ARCH=macosx-aarch64 ;;
  *) echo "Unsupported platform: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

step "Python virtual environment"
command -v python3 >/dev/null || { echo "Python 3.11+ not found" >&2; exit 1; }
[ -d "$ROOT/.venv" ] || python3 -m venv "$ROOT/.venv"
"$BIN/python" -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ required"'
"$BIN/pip" install --quiet --upgrade pip
"$BIN/pip" install --quiet -r "$ROOT/requirements.txt"
ok "venv ready, app dependencies installed"

# Semgrep's dependencies clash with the app's (it pins a newer starlette than
# FastAPI allows), so it gets its OWN venv; only its launcher goes on the PATH.
step "Semgrep"
SEMGREP_VENV="$TOOLS/semgrep-venv"
if [ ! -x "$SEMGREP_VENV/bin/semgrep" ]; then
  python3 -m venv "$SEMGREP_VENV"
  "$SEMGREP_VENV/bin/pip" install --quiet --upgrade pip
  "$SEMGREP_VENV/bin/pip" install --quiet semgrep
fi
ln -sf "$SEMGREP_VENV/bin/semgrep" "$BIN/semgrep"
ok "installed to .tools/semgrep-venv (isolated), symlinked into .venv/bin"

step "SCC $SCC_VERSION"
if [ ! -x "$BIN/scc" ]; then
  curl -fsSL -o /tmp/scc.tar.gz \
    "https://github.com/boyter/scc/releases/download/v$SCC_VERSION/$SCC_ASSET"
  tar -xzf /tmp/scc.tar.gz -C "$BIN" scc
  chmod +x "$BIN/scc"; rm /tmp/scc.tar.gz
fi
ok "installed to .venv/bin/scc"

step "Snyk CLI"
if [ ! -x "$BIN/snyk" ]; then
  curl -fsSL -o "$BIN/snyk" "https://static.snyk.io/cli/latest/$SNYK_BIN"
  chmod +x "$BIN/snyk"
fi
ok "installed to .venv/bin/snyk (paste your token in Settings to enable it)"

step "sonar-scanner $SS_VERSION"
SS_DIR="$TOOLS/sonar-scanner-$SS_VERSION-$SS_ARCH"
if [ ! -d "$SS_DIR" ]; then
  curl -fsSL -o /tmp/sonar-scanner.zip \
    "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-$SS_VERSION-$SS_ARCH.zip"
  mkdir -p "$TOOLS"
  unzip -q -o /tmp/sonar-scanner.zip -d "$TOOLS"
  rm /tmp/sonar-scanner.zip
fi
ln -sf "$SS_DIR/bin/sonar-scanner" "$BIN/sonar-scanner"
ok "installed to .tools/ with a symlink in .venv/bin"

step "Verifying installed tools"
ok "semgrep $("$BIN/semgrep" --version | head -1)"
ok "scc     $("$BIN/scc" --version)"
ok "snyk    $("$BIN/snyk" --version)"
ok "sonar-scanner (symlinked; verified on first scan — JVM boot is slow)"

step "Docker (optional — only needed for the SonarQube server)"
if command -v docker >/dev/null; then
  ok "Docker found. Start SonarQube with: docker compose up -d sonarqube"
else
  printf '    \033[33mWARNING: Docker not found. SonarQube scans need it; the other tools work without it.\033[0m\n'
fi

printf '\n\033[36mDone. Next steps:
  1. source .venv/bin/activate
  2. docker compose up -d sonarqube        # optional, for SonarQube scans
  3. uvicorn app.main:app --host 127.0.0.1 --port 8000
  4. Open http://localhost:8000  (paste your Snyk token in Settings -> Scanner tokens)\033[0m\n'