cat > /tmp/install-wazuh-agent-ubuntu.sh <<'BASH'
#!/usr/bin/env bash
set -euo pipefail

# =========================
# CONFIG (ajuste se quiser)
# =========================
WAZUH_MANAGER_FQDN="ls8lj27cyp3a.cloud.wazuh.com"
WAZUH_AGENT_GROUP="servidores_windows"   # pode trocar para "servidores_linux" se preferir
WAZUH_DEST_IP="3.19.177.148"
WAZUH_PORTS=(1514 1515 55000)

BASE_DIR="/tmp/wazuh"
LOG_DIR="/var/log/wazuh-install"
TS="$(date +'%Y%m%d-%H%M%S')"

# =========================
# FUNÇÕES
# =========================
log() {
  local level="$1"; shift
  local msg="$*"
  local line="[$(date +'%Y-%m-%d %H:%M:%S')] [$level] $msg"
  echo "$line" | tee -a "$LOG_FILE" >/dev/null
}

die() { log "ERROR" "$*"; exit 1; }

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Execute como root (ex: sudo bash $0)" >&2
    exit 1
  fi
}

get_primary_ip() {
  # tenta pegar o IP usado para sair para a Internet
  local ip
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
  if [[ -z "${ip:-}" ]]; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  echo "${ip:-NOIP}"
}

tcp_check() {
  local host="$1" port="$2"
  # usa /dev/tcp (bash) com timeout curto
  if timeout 3 bash -c "cat < /dev/null > /dev/tcp/${host}/${port}" 2>/dev/null; then
    return 0
  fi
  return 1
}

# =========================
# MAIN
# =========================
require_root

mkdir -p "$BASE_DIR" "$LOG_DIR"
HOSTNAME_SHORT="$(hostname -s 2>/dev/null || hostname)"
PRIMARY_IP="$(get_primary_ip)"

LOG_FILE="${LOG_DIR}/WazuhAgent_Ubuntu_${HOSTNAME_SHORT}_${PRIMARY_IP}_${TS}.log"
touch "$LOG_FILE" || { echo "Sem permissão para escrever em $LOG_FILE"; exit 1; }

log "INFO" "==== WAZUH AGENT INSTALL (UBUNTU) - INÍCIO ===="
log "INFO" "Hostname: ${HOSTNAME_SHORT}"
log "INFO" "IP primário: ${PRIMARY_IP}"
log "INFO" "Data/Hora: $(date)"
log "INFO" "Manager (FQDN): ${WAZUH_MANAGER_FQDN}"
log "INFO" "Grupo: ${WAZUH_AGENT_GROUP}"
log "INFO" "Destino (IP hard): ${WAZUH_DEST_IP}"
log "INFO" "Portas: TCP/${WAZUH_PORTS[*]}"

# Senha: pega do env ou pergunta (sem eco)
if [[ -z "${WAZUH_REG_PASSWORD:-}" ]]; then
  log "WARN" "WAZUH_REG_PASSWORD não definido no ambiente. Solicitando no prompt..."
  read -r -s -p "Digite WAZUH_REG_PASSWORD (não será exibido): " WAZUH_REG_PASSWORD
  echo
fi
[[ -n "${WAZUH_REG_PASSWORD:-}" ]] || die "Registration password vazio. Abortei."

# Evidência de DNS do manager
log "INFO" "ETAPA 1 - Resolução DNS do Manager"
if getent hosts "${WAZUH_MANAGER_FQDN}" | tee -a "$LOG_FILE" >/dev/null; then
  log "OK" "DNS ok para ${WAZUH_MANAGER_FQDN}"
else
  log "WARN" "Não consegui resolver ${WAZUH_MANAGER_FQDN} via getent (pode ser DNS/hosts)."
fi

# Firewall (UFW) — só mexe se ativo (boa governança). Outbound costuma ser allow por padrão.
log "INFO" "ETAPA 2 - Firewall (UFW) - evidência e (se ativo) liberação OUTBOUND específica"
if command -v ufw >/dev/null 2>&1; then
  ufw status verbose | tee -a "$LOG_FILE" >/dev/null || true
  if ufw status | grep -qi "Status: active"; then
    for p in "${WAZUH_PORTS[@]}"; do
      # regra out específica (se já existir, UFW normalmente ignora/duplica sem quebrar)
      ufw allow out to "${WAZUH_DEST_IP}" port "${p}" proto tcp >/dev/null 2>&1 || true
      log "OK" "UFW: allow out tcp ${WAZUH_DEST_IP}:${p} (best-effort)"
    done
    ufw status verbose | tee -a "$LOG_FILE" >/dev/null || true
  else
    log "INFO" "UFW instalado mas não está ativo — não alterei regras."
  fi
else
  log "INFO" "UFW não instalado — não apliquei regras (em geral Ubuntu permite outbound por padrão)."
fi

# Conectividade TCP pro IP/portas exigidas
log "INFO" "ETAPA 3 - Teste de conectividade TCP (Destino IP hard)"
for p in "${WAZUH_PORTS[@]}"; do
  if tcp_check "${WAZUH_DEST_IP}" "${p}"; then
    log "OK" "TCP OK: ${WAZUH_DEST_IP}:${p}"
  else
    log "WARN" "TCP FALHOU: ${WAZUH_DEST_IP}:${p} (roteamento/firewall/proxy?)"
  fi
done

# Instala pré-requisitos e repo Wazuh (apt)
log "INFO" "ETAPA 4 - Repositório Wazuh (apt) + pré-requisitos"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y | tee -a "$LOG_FILE" >/dev/null

apt-get install -y gnupg apt-transport-https curl ca-certificates | tee -a "$LOG_FILE" >/dev/null
log "OK" "Pacotes base instalados (gnupg, apt-transport-https, curl, ca-certificates)."

mkdir -p /usr/share/keyrings
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
  | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
  && chmod 644 /usr/share/keyrings/wazuh.gpg
log "OK" "GPG key do Wazuh importada em /usr/share/keyrings/wazuh.gpg"

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | tee /etc/apt/sources.list.d/wazuh.list >/dev/null
log "OK" "Repo adicionado em /etc/apt/sources.list.d/wazuh.list"

apt-get update -y | tee -a "$LOG_FILE" >/dev/null
log "OK" "apt-get update finalizado."

# Instala agente com enrollment via deployment variables
log "INFO" "ETAPA 5 - Instalação do wazuh-agent + enrollment (senha REDACTED)"
# Importante: NÃO logar a senha. Passa via env.
WAZUH_MANAGER="${WAZUH_MANAGER_FQDN}" \
WAZUH_REGISTRATION_SERVER="${WAZUH_MANAGER_FQDN}" \
WAZUH_REGISTRATION_PASSWORD="${WAZUH_REG_PASSWORD}" \
WAZUH_AGENT_GROUP="${WAZUH_AGENT_GROUP}" \
apt-get install -y wazuh-agent | tee -a "$LOG_FILE" >/dev/null

log "OK" "wazuh-agent instalado."

# Evidência versão/pacote
log "INFO" "Evidência: dpkg -l wazuh-agent"
dpkg -l wazuh-agent | tee -a "$LOG_FILE" >/dev/null || true

# Start/enable service
log "INFO" "ETAPA 6 - Enable/Start serviço"
systemctl daemon-reload || true
systemctl enable wazuh-agent | tee -a "$LOG_FILE" >/dev/null || true
systemctl restart wazuh-agent | tee -a "$LOG_FILE" >/dev/null || true
sleep 2

# Verificações do serviço
log "INFO" "ETAPA 7 - Validação do serviço"
if systemctl is-active --quiet wazuh-agent; then
  log "OK" "Serviço wazuh-agent está Running."
else
  log "ERROR" "Serviço wazuh-agent NÃO está ativo."
  systemctl --no-pager status wazuh-agent | tee -a "$LOG_FILE" >/dev/null || true
  journalctl -u wazuh-agent --no-pager -n 120 | tee -a "$LOG_FILE" >/dev/null || true
  die "Falha ao iniciar wazuh-agent. Verifique logs acima."
fi

log "INFO" "Evidência: systemctl status wazuh-agent"
systemctl --no-pager status wazuh-agent | tee -a "$LOG_FILE" >/dev/null || true

log "INFO" "Evidência: journalctl -u wazuh-agent (últimas 120 linhas)"
journalctl -u wazuh-agent --no-pager -n 120 | tee -a "$LOG_FILE" >/dev/null || true

# Evidência log do agente (ossec.log costuma existir)
log "INFO" "ETAPA 8 - Evidência logs do agente (/var/ossec/logs)"
if [[ -d /var/ossec/logs ]]; then
  ls -la /var/ossec/logs | tee -a "$LOG_FILE" >/dev/null || true
  if [[ -f /var/ossec/logs/ossec.log ]]; then
    log "INFO" "Tail /var/ossec/logs/ossec.log (últimas 60 linhas)"
    tail -n 60 /var/ossec/logs/ossec.log | tee -a "$LOG_FILE" >/dev/null || true
  else
    log "WARN" "Não encontrei /var/ossec/logs/ossec.log (pode variar por versão)."
  fi
else
  log "WARN" "/var/ossec/logs não encontrado (instalação incompleta?)."
fi

# (Opcional) Trava updates do wazuh-agent (governança)
log "INFO" "ETAPA 9 - Governança: segurar updates do wazuh-agent (hold)"
echo "wazuh-agent hold" | dpkg --set-selections || true
log "OK" "wazuh-agent marcado como HOLD (evita upgrade acidental)."

# Limpa senha da memória do processo (higiene)
unset WAZUH_REG_PASSWORD || true

log "OK" "==== WAZUH AGENT INSTALL (UBUNTU) - SUCESSO ===="
log "INFO" "LOG: ${LOG_FILE}"
BASH

chmod +x /tmp/install-wazuh-agent-ubuntu.sh
sudo /tmp/install-wazuh-agent-ubuntu.sh
