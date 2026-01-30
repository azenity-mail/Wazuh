#!/usr/bin/env bash
set -euo pipefail

# ===== CONFIG =====
WAZUH_MANAGER_FQDN="ls8lj27cyp3a.cloud.wazuh.com"
WAZUH_AGENT_GROUP="servidores_linux"
WAZUH_DEST_IP="3.19.177.148"
WAZUH_PORTS=(1514 1515 55000)

LOG_DIR="/var/log/wazuh-install"
TS="$(date +'%Y%m%d-%H%M%S')"

log() { local lvl="$1"; shift; echo "[$(date +'%F %T')] [$lvl] $*" | tee -a "$LOG_FILE" >/dev/null; }
die() { log "ERROR" "$*"; exit 1; }

require_root(){ [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Execute como root (sudo -i)."; }

get_primary_ip(){
  local ip
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
  [[ -n "${ip:-}" ]] || ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  echo "${ip:-NOIP}"
}

tcp_check(){
  local host="$1" port="$2"
  timeout 3 bash -c "cat < /dev/null > /dev/tcp/${host}/${port}" 2>/dev/null
}

# ===== MAIN =====
require_root
mkdir -p "$LOG_DIR"

HOST="$(hostname -s 2>/dev/null || hostname)"
IP="$(get_primary_ip)"
LOG_FILE="${LOG_DIR}/WazuhAgent_Debian13_${HOST}_${IP}_${TS}.log"
touch "$LOG_FILE" || die "Sem permissão para escrever em $LOG_FILE"

log "INFO" "==== WAZUH AGENT INSTALL (DEBIAN 13 / PROXMOX) - INÍCIO ===="
log "INFO" "Host=$HOST IP=$IP"
log "INFO" "Manager=$WAZUH_MANAGER_FQDN Group=$WAZUH_AGENT_GROUP"
log "INFO" "DestinoIP=$WAZUH_DEST_IP Portas=TCP/${WAZUH_PORTS[*]}"
log "INFO" "OS: $(cat /etc/os-release | egrep 'PRETTY_NAME|VERSION_ID' | tr '\n' ' ')"

# Senha por env ou prompt
if [[ -z "${WAZUH_REG_PASSWORD:-}" ]]; then
  log "WARN" "WAZUH_REG_PASSWORD não definido. Solicitando (não será logado)."
  read -r -s -p "Digite WAZUH_REG_PASSWORD: " WAZUH_REG_PASSWORD; echo
fi
[[ -n "${WAZUH_REG_PASSWORD:-}" ]] || die "Senha vazia."

# DNS evidence
log "INFO" "ETAPA 1 - DNS do manager"
getent hosts "$WAZUH_MANAGER_FQDN" | tee -a "$LOG_FILE" >/dev/null || log "WARN" "Falha de DNS (getent) para $WAZUH_MANAGER_FQDN"

# TCP checks (IP e FQDN)
log "INFO" "ETAPA 2 - Teste TCP para IP fixo"
for p in "${WAZUH_PORTS[@]}"; do
  if tcp_check "$WAZUH_DEST_IP" "$p"; then log "OK" "TCP OK $WAZUH_DEST_IP:$p"
  else log "WARN" "TCP FAIL $WAZUH_DEST_IP:$p"; fi
done

log "INFO" "ETAPA 3 - Teste TCP para FQDN (caminho real)"
for p in "${WAZUH_PORTS[@]}"; do
  if tcp_check "$WAZUH_MANAGER_FQDN" "$p"; then log "OK" "TCP OK $WAZUH_MANAGER_FQDN:$p"
  else log "WARN" "TCP FAIL $WAZUH_MANAGER_FQDN:$p"; fi
done

# Repo + instalação
log "INFO" "ETAPA 4 - Repo Wazuh + install"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y | tee -a "$LOG_FILE" >/dev/null
apt-get install -y curl ca-certificates gnupg | tee -a "$LOG_FILE" >/dev/null

mkdir -p /usr/share/keyrings
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
  | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
  && chmod 644 /usr/share/keyrings/wazuh.gpg
log "OK" "GPG key importada."

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list
apt-get update -y | tee -a "$LOG_FILE" >/dev/null

log "INFO" "ETAPA 5 - Instalação do wazuh-agent (senha REDACTED)"
WAZUH_MANAGER="$WAZUH_MANAGER_FQDN" \
WAZUH_REGISTRATION_SERVER="$WAZUH_MANAGER_FQDN" \
WAZUH_REGISTRATION_PASSWORD="$WAZUH_REG_PASSWORD" \
WAZUH_AGENT_GROUP="$WAZUH_AGENT_GROUP" \
apt-get install -y wazuh-agent | tee -a "$LOG_FILE" >/dev/null

log "OK" "wazuh-agent instalado."
dpkg -l wazuh-agent | tee -a "$LOG_FILE" >/dev/null || true

# Serviço
log "INFO" "ETAPA 6 - Enable/Start service"
systemctl daemon-reload || true
systemctl enable wazuh-agent | tee -a "$LOG_FILE" >/dev/null || true
systemctl restart wazuh-agent | tee -a "$LOG_FILE" >/dev/null || true
sleep 2

if systemctl is-active --quiet wazuh-agent; then
  log "OK" "Serviço wazuh-agent Running."
else
  log "ERROR" "Serviço wazuh-agent NÃO está ativo."
  systemctl --no-pager status wazuh-agent | tee -a "$LOG_FILE" >/dev/null || true
  journalctl -u wazuh-agent --no-pager -n 160 | tee -a "$LOG_FILE" >/dev/null || true
  die "Falha ao iniciar wazuh-agent."
fi

log "INFO" "ETAPA 7 - Evidências"
systemctl --no-pager status wazuh-agent | tee -a "$LOG_FILE" >/dev/null || true
journalctl -u wazuh-agent --no-pager -n 160 | tee -a "$LOG_FILE" >/dev/null || true
[[ -f /var/ossec/logs/ossec.log ]] && tail -n 80 /var/ossec/logs/ossec.log | tee -a "$LOG_FILE" >/dev/null || log "WARN" "ossec.log não encontrado."

unset WAZUH_REG_PASSWORD || true
log "OK" "==== SUCESSO ===="
log "INFO" "LOG: $LOG_FILE"
