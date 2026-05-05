#!/bin/bash
# Automated deployment script for agentic-nids and honeypot on MicroK8s.
# Installs Ollama, downloads Gemma 4, then deploys the full stack.
set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────

RESET="\033[0m"
BOLD="\033[1m"
RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
WHITE="\033[1;37m"

ok()      { echo -e "${GREEN}  [✔]${RESET} $*"; }
info()    { echo -e "${CYAN}  [ℹ]${RESET} $*"; }
warn()    { echo -e "${YELLOW}  [⚠]${RESET} $*"; }
err()     { echo -e "${RED}  [✘]${RESET} $*" >&2; }
section() { echo -e "\n${BOLD}${WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n  ▶  $*\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"; }
step()    { echo -e "\n  ${BOLD}${YELLOW}┌─ $* ${RESET}"; }
die()     { err "$*"; exit 1; }

# ── Config ────────────────────────────────────────────────────────────────────

GEMMA_MODEL="${GEMMA_MODEL:-gemma4}"
OLLAMA_HOST="http://localhost:11434"
OLLAMA_STARTUP_TIMEOUT=30

# ── Banner ────────────────────────────────────────────────────────────────────

echo -e "${BOLD}${CYAN}"
echo "  ╔═══════════════════════════════════════╗"
echo "  ║       Agentic NIDS  — Deploy          ║"
echo "  ╚═══════════════════════════════════════╝"
echo -e "${RESET}"
info "Model   : ${GEMMA_MODEL}"
info "Ollama  : ${OLLAMA_HOST}"
info "User    : ${USER}"
info "Host    : $(hostname)"
echo ""

# ── Ollama ────────────────────────────────────────────────────────────────────

section "Ollama"

install_ollama() {
  step "Install Ollama"
  if command -v ollama &>/dev/null; then
    local ver
    ver=$(ollama --version 2>&1 | head -1)
    ok "Ollama already installed — ${ver}"
    return
  fi
  info "Ollama not found, installing via official install script..."
  curl -fsSL https://ollama.com/install.sh | sh
  ok "Ollama installed — $(ollama --version 2>&1 | head -1)"
}

start_ollama() {
  step "Start Ollama daemon"
  if pgrep -x ollama &>/dev/null; then
    ok "Ollama daemon is already running."
    return
  fi
  info "Starting Ollama daemon (log → /tmp/ollama.log)..."
  ollama serve &>/tmp/ollama.log &
  local i=0
  until curl -sf "${OLLAMA_HOST}/" &>/dev/null; do
    sleep 1
    i=$((i + 1))
    if [ "$i" -ge "${OLLAMA_STARTUP_TIMEOUT}" ]; then
      die "Ollama did not respond after ${OLLAMA_STARTUP_TIMEOUT}s. Check /tmp/ollama.log."
    fi
    info "Waiting for Ollama API... (${i}/${OLLAMA_STARTUP_TIMEOUT}s)"
  done
  ok "Ollama daemon ready at ${OLLAMA_HOST}."
}

download_gemma() {
  step "Download ${GEMMA_MODEL}"
  info "Pulling ${GEMMA_MODEL} — this may take several minutes on the first run."
  info "Progress is streamed from Ollama below:"
  echo ""
  ollama pull "${GEMMA_MODEL}"
  echo ""
  ok "Model ${GEMMA_MODEL} is ready."
  echo ""
  echo -e "  ${CYAN}Agent config to use this model:${RESET}"
  echo -e "  ${WHITE}    provider = vllm${RESET}"
  echo -e "  ${WHITE}    base_url = ${OLLAMA_HOST}/v1${RESET}"
  echo -e "  ${WHITE}    model    = ${GEMMA_MODEL}${RESET}"
}

install_ollama
start_ollama
download_gemma

# ── MicroK8s ──────────────────────────────────────────────────────────────────

section "MicroK8s"

step "Install MicroK8s"
if ! command -v microk8s.kubectl &>/dev/null; then
  info "MicroK8s not found — installing via snap..."
  sudo snap install microk8s --classic || die "Failed to install MicroK8s."
  sudo usermod -a -G microk8s "$USER"
  sudo chown -f -R "$USER" ~/.kube
  ok "MicroK8s installed."
  warn "You may need to log out and back in for group changes to take effect."
else
  ok "MicroK8s is already installed."
fi

step "Configure kubectl"
if ! command -v kubectl &>/dev/null; then
  info "kubectl not found — creating snap alias..."
  sudo snap alias microk8s.kubectl kubectl \
    || sudo ln -s "$(which microk8s.kubectl)" /usr/local/bin/kubectl
  ok "kubectl alias created."
else
  ok "kubectl is available."
fi

# ── Helm ──────────────────────────────────────────────────────────────────────

section "Helm"

step "Install Helm"
if ! command -v helm &>/dev/null; then
  info "Helm not found — installing via snap..."
  sudo snap install helm --classic || die "Failed to install Helm."
  ok "Helm installed — $(helm version --short)."
else
  ok "Helm is already installed — $(helm version --short)."
fi

# ── Cluster ───────────────────────────────────────────────────────────────────

section "Cluster"

step "Start cluster"
info "Starting MicroK8s..."
sudo microk8s start
ok "MicroK8s started."

step "Enable addons"
info "Enabling dns, storage..."
sudo microk8s enable dns storage
ok "Addons enabled."

step "Export kubeconfig"
info "Writing kubeconfig to ~/.kube/config..."
sudo microk8s config > ~/.kube/config
sudo chown "$USER" ~/.kube/config
ok "Kubeconfig written."

# ── Deploy ────────────────────────────────────────────────────────────────────

section "Deploy"

step "Deploy agentic-nids"
info "Namespace  : agentic-nids"
info "LLM model  : ${GEMMA_MODEL}"
info "LLM baseUrl: ${OLLAMA_HOST}/v1"
helm upgrade --install agentic-nids ../helm/agentic-nids \
  -n agentic-nids --create-namespace \
  --set llm.provider=vllm \
  --set llm.model="${GEMMA_MODEL}" \
  --set llm.baseUrl="${OLLAMA_HOST}/v1"
ok "agentic-nids deployed."

step "Deploy honeypot"
info "Applying manifests from infra/microk8s/honeypot/..."
kubectl apply -f ../microk8s/honeypot/
ok "Honeypot manifests applied."

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}${BOLD}  ✔  Deployment complete.${RESET}"
echo ""
