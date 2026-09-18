#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Owlet AI — Local Runner Bootstrap
#
# Run this script inside Kali Linux (WSL or native) to install all dependencies,
# configure the backend, and optionally install security scanning tools.
#
# Usage:
#   bash setup.sh          # interactive setup
#   bash setup.sh --quiet  # non-interactive (uses defaults / existing .env)
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$REPO_DIR/backend"
FRONTEND="$REPO_DIR/frontend"
ENV_FILE="$BACKEND/.env"
QUIET=false
[[ "${1:-}" == "--quiet" ]] && QUIET=true

# ── Colour helpers ────────────────────────────────────────────────────────────

RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"
BLUE="\033[0;34m"; BOLD="\033[1m"; RESET="\033[0m"

info()    { echo -e "${BLUE}[info]${RESET}  $*"; }
ok()      { echo -e "${GREEN}[ok]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[warn]${RESET}  $*"; }
error()   { echo -e "${RED}[error]${RESET} $*" >&2; }
section() { echo -e "\n${BOLD}══ $* ══${RESET}"; }
prompt()  { read -rp "$1 " "$2"; }

# ── OS detection ──────────────────────────────────────────────────────────────

IS_KALI=false
IS_DEBIAN=false
OS_NAME="unknown"

if [[ -f /etc/os-release ]]; then
  . /etc/os-release
  OS_NAME="${ID:-unknown}"
  [[ "${ID:-}" == "kali" ]] && IS_KALI=true
  [[ "${ID_LIKE:-}" == *"debian"* || "${ID:-}" == "debian" || "${ID:-}" == "ubuntu" ]] && IS_DEBIAN=true
  [[ "${ID:-}" == "kali" ]] && IS_DEBIAN=true
fi

# ── Prerequisites ─────────────────────────────────────────────────────────────

section "Prerequisites"

if ! command -v python3 &>/dev/null; then
  error "python3 not found. Install it first: sudo apt install python3"
  exit 1
fi

PYTHON_VER=$(python3 --version 2>&1)
ok "Python: $PYTHON_VER"

if ! command -v pip3 &>/dev/null; then
  info "pip3 not found — installing…"
  if $IS_DEBIAN; then
    sudo apt-get install -y python3-pip
  else
    error "pip3 not found. Install it manually."
    exit 1
  fi
fi
ok "pip3: $(pip3 --version | awk '{print $2}')"

if ! command -v git &>/dev/null; then
  if $IS_DEBIAN; then
    sudo apt-get install -y git
  else
    error "git not found."
    exit 1
  fi
fi
ok "git: $(git --version)"

if $IS_KALI; then
  ok "OS: Kali Linux — apt packages available for all scanner tools"
else
  warn "OS: $OS_NAME — Go binaries will be downloaded for most tools"
fi

# ── Python dependencies ───────────────────────────────────────────────────────

section "Python dependencies"
REQ="$BACKEND/requirements.txt"
if [[ -f "$REQ" ]]; then
  info "Installing backend requirements…"
  pip3 install --user -r "$REQ"
  ok "Python packages installed"
else
  warn "requirements.txt not found — skipping pip install"
fi

# ── .env configuration ────────────────────────────────────────────────────────

section "Backend configuration"

if [[ -f "$ENV_FILE" ]] && $QUIET; then
  ok ".env already exists — using it as-is"
else
  if [[ -f "$ENV_FILE" ]]; then
    warn ".env already exists."
    if ! $QUIET; then
      prompt "Overwrite it? (y/N)" OVERWRITE
      [[ "${OVERWRITE,,}" != "y" ]] && { ok "Keeping existing .env"; }
    fi
  fi

  if [[ ! -f "$ENV_FILE" ]] || [[ "${OVERWRITE,,}" == "y" ]]; then
    info "We'll collect a few values to configure Owlet."
    echo ""

    # Azure AD
    prompt "Azure AD Tenant ID (from Azure portal > App registrations):" TENANT_ID
    prompt "Azure AD Client ID (App registration client/application ID):" CLIENT_ID

    # AI provider (at least one needed)
    echo ""
    info "AI provider — enter at least one. Press Enter to skip."
    prompt "OpenAI API key (sk-...):" OPENAI_KEY
    prompt "Azure OpenAI endpoint (https://your-resource.openai.azure.com):" AZ_OAI_ENDPOINT
    prompt "Azure OpenAI API key:" AZ_OAI_KEY
    prompt "Azure OpenAI deployment name (e.g. gpt-4o):" AZ_OAI_DEPLOY
    prompt "Anthropic API key (sk-ant-...):" ANTHROPIC_KEY
    prompt "Google Gemini API key:" GEMINI_KEY

    # Cloud (optional)
    echo ""
    info "Cloud connectors (optional — press Enter to skip)"
    prompt "Azure Subscription ID:" AZ_SUB_ID
    prompt "AWS Access Key ID:" AWS_KEY_ID
    prompt "AWS Secret Access Key:" AWS_SECRET

    # GitHub (for scanners that still use GitHub Actions)
    echo ""
    info "GitHub (for scanners that still use GitHub Actions)"
    prompt "GitHub token (ghp_...):" GITHUB_TOKEN
    prompt "GitHub owner/org (e.g. gulatidh):" GITHUB_OWNER
    prompt "GitHub repo name (e.g. NexGenCyberAI):" GITHUB_REPO

    cat > "$ENV_FILE" <<EOF
# ── Auth ─────────────────────────────────────────────────────────────────────
AZURE_TENANT_ID=${TENANT_ID}
AZURE_CLIENT_ID=${CLIENT_ID}

# ── Database (SQLite default — change to mssql+pymssql://... for Azure SQL) ──
DATABASE_URL=sqlite:///${BACKEND}/nexgencyberai.db

# ── AI providers ─────────────────────────────────────────────────────────────
OPENAI_API_KEY=${OPENAI_KEY}
AZURE_OPENAI_ENDPOINT=${AZ_OAI_ENDPOINT}
AZURE_OPENAI_API_KEY=${AZ_OAI_KEY}
AZURE_OPENAI_DEPLOYMENT=${AZ_OAI_DEPLOY}
ANTHROPIC_API_KEY=${ANTHROPIC_KEY}
GOOGLE_GEMINI_API_KEY=${GEMINI_KEY}

# ── Cloud connectors ──────────────────────────────────────────────────────────
AZURE_SUBSCRIPTION_ID=${AZ_SUB_ID}
AWS_ACCESS_KEY_ID=${AWS_KEY_ID}
AWS_SECRET_ACCESS_KEY=${AWS_SECRET}

# ── GitHub Actions (for cloud-based scanners) ─────────────────────────────────
GITHUB_TOKEN=${GITHUB_TOKEN}
GITHUB_OWNER=${GITHUB_OWNER}
GITHUB_REPO=${GITHUB_REPO}

# ── CORS ─────────────────────────────────────────────────────────────────────
ALLOWED_ORIGINS=["http://localhost:3000","http://localhost:5173"]

# ── Misc ─────────────────────────────────────────────────────────────────────
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
EOF
    ok ".env written to $ENV_FILE"
  fi
fi

# ── Scanner tools ─────────────────────────────────────────────────────────────

section "Scanner tools"

OWLET_BIN="$HOME/.owlet/bin"
mkdir -p "$OWLET_BIN"
LOCAL_BIN="$HOME/.local/bin"
export PATH="$OWLET_BIN:$LOCAL_BIN:$PATH"

install_apt() {
  local pkg="$1"
  if dpkg -l "$pkg" &>/dev/null 2>&1; then
    ok "$pkg already installed"
    return
  fi
  info "Installing $pkg via apt…"
  if sudo apt-get install -y "$pkg" &>/dev/null; then
    ok "$pkg installed"
  else
    warn "$pkg install failed — skipping"
  fi
}

install_binary() {
  # $1=name $2=url $3=archive_type(tar|zip) $4=binary_name_in_archive
  local name="$1" url="$2" atype="$3" binname="${4:-$1}"
  if command -v "$name" &>/dev/null; then
    ok "$name already in PATH"
    return
  fi
  info "Downloading $name…"
  local tmp
  tmp=$(mktemp -d)
  local archive="$tmp/${url##*/}"
  if wget -q "$url" -O "$archive" 2>/dev/null || curl -sL "$url" -o "$archive" 2>/dev/null; then
    if [[ "$atype" == "tar" ]]; then
      tar -xzf "$archive" -C "$tmp" 2>/dev/null || tar -xf "$archive" -C "$tmp" 2>/dev/null
    else
      unzip -q "$archive" -d "$tmp"
    fi
    local bin
    bin=$(find "$tmp" -name "$binname" -type f 2>/dev/null | head -1)
    if [[ -n "$bin" ]]; then
      cp "$bin" "$OWLET_BIN/$name"
      chmod +x "$OWLET_BIN/$name"
      ok "$name installed to $OWLET_BIN/$name"
    else
      warn "$name binary not found in archive"
    fi
  else
    warn "Failed to download $name"
  fi
  rm -rf "$tmp"
}

INSTALL_TOOLS=true
if ! $QUIET; then
  prompt "Install scanner tools now? (Y/n)" INST_ANS
  [[ "${INST_ANS,,}" == "n" ]] && INSTALL_TOOLS=false
fi

if $INSTALL_TOOLS; then
  if $IS_DEBIAN; then
    # Update apt cache once
    info "Updating apt package list…"
    sudo apt-get update -q &>/dev/null

    # Nmap
    install_apt "nmap"

    # Trivy — Aqua Security apt repo for non-Kali, or direct for Kali
    if $IS_KALI; then
      install_apt "trivy" 2>/dev/null || \
        install_binary "trivy" \
          "https://github.com/aquasecurity/trivy/releases/download/v0.57.1/trivy_0.57.1_Linux-64bit.tar.gz" \
          "tar" "trivy"
    else
      install_binary "trivy" \
        "https://github.com/aquasecurity/trivy/releases/download/v0.57.1/trivy_0.57.1_Linux-64bit.tar.gz" \
        "tar" "trivy"
    fi

    # Semgrep via pip
    if ! command -v semgrep &>/dev/null; then
      info "Installing semgrep via pip…"
      pip3 install --user semgrep &>/dev/null && ok "semgrep installed" || warn "semgrep install failed"
    else
      ok "semgrep already installed"
    fi
  fi

  # Go static binaries — always download to OWLET_BIN
  install_binary "gitleaks" \
    "https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz" \
    "tar" "gitleaks"

  install_binary "trufflehog" \
    "https://github.com/trufflesecurity/trufflehog/releases/download/v3.88.1/trufflehog_3.88.1_linux_amd64.tar.gz" \
    "tar" "trufflehog"

  install_binary "nuclei" \
    "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip" \
    "zip" "nuclei"

  # OpenVAS — Kali only (package is kali-specific)
  if $IS_KALI; then
    if ! command -v gvm-setup &>/dev/null; then
      info "Installing OpenVAS / GVM (Kali)…"
      if sudo apt-get install -y openvas &>/dev/null; then
        ok "OpenVAS installed"
        info "Run 'sudo gvm-setup' to download the NVT feed (~20 min first time)"
        info "Then 'sudo gvm-start' to start the daemon before running OpenVAS scans"
      else
        warn "OpenVAS install failed — install manually: sudo apt install openvas"
      fi
    else
      ok "OpenVAS / GVM already installed"
    fi
    # gvm-tools Python package (provides gvm-cli)
    pip3 install --user gvm-tools &>/dev/null && ok "gvm-tools installed" || true
  else
    warn "OpenVAS is only available on Kali Linux via apt — skipping"
  fi
fi

# ── PATH reminder ─────────────────────────────────────────────────────────────

SHELL_RC="$HOME/.bashrc"
[[ -n "${ZSH_VERSION:-}" ]] && SHELL_RC="$HOME/.zshrc"

EXPORT_LINE="export PATH=\"\$HOME/.owlet/bin:\$HOME/.local/bin:\$PATH\""
if ! grep -qF ".owlet/bin" "$SHELL_RC" 2>/dev/null; then
  echo "" >> "$SHELL_RC"
  echo "# Owlet local scanner tools" >> "$SHELL_RC"
  echo "$EXPORT_LINE" >> "$SHELL_RC"
  ok "PATH updated in $SHELL_RC"
fi

# ── Start backend ─────────────────────────────────────────────────────────────

section "Start backend"

START_BACKEND=false
if ! $QUIET; then
  prompt "Start the Owlet backend now? (Y/n)" START_ANS
  [[ "${START_ANS,,}" != "n" ]] && START_BACKEND=true
else
  START_BACKEND=true
fi

if $START_BACKEND; then
  info "Starting backend on http://0.0.0.0:8000 …"
  info "(Press Ctrl+C to stop, or run in a separate terminal)"
  echo ""
  cd "$BACKEND"
  exec python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
fi

# ── Done ──────────────────────────────────────────────────────────────────────

section "Done"
echo ""
echo -e "${GREEN}Owlet local runner is set up.${RESET}"
echo ""
echo "  Start the backend:   cd $BACKEND && python3 -m uvicorn main:app --host 0.0.0.0 --port 8000"
echo "  Start the frontend:  cd $FRONTEND && npm run dev"
echo ""
echo "  Then open: http://localhost:5173  (or port 3000)"
echo ""
echo "  In the portal, go to Platform → Local Runner to configure which"
echo "  scanners run locally vs via GitHub Actions."
echo ""
