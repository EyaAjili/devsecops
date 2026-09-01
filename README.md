# Prototype DevSecOps IA — Kubernetes (stage AICYOU)

Prototype de détection d'anomalies et de remédiation automatique sur un cluster Kind : Falco → Falcosidekick → Flask/IA hybride (Random Forest + UBA) → quarantaine Cilium + ticket Jira + email. Stagiaire : Eya Ajili (ESPRIT).

## Démarrage

```bash
cd terraform
terraform init && terraform apply
export KUBECONFIG=$PWD/devsecops-lab-config

cd ../src
python generate_smart_testdata.py
python train.py

export GMAIL_APP_PASSWORD=...
export JIRA_BASE_URL=https://xxxx.atlassian.net
export JIRA_EMAIL=...
export JIRA_API_TOKEN=...
export JIRA_PROJECT_KEY=SEC
python collector.py
```

Grafana : `kubectl -n monitoring port-forward svc/kube-prometheus-stack-grafana 3000:80` puis importer `config/grafana_dashboard.json`.

## Scénarios d'attaque (phase 4 de l'offre)

```bash
chmod +x scripts/attack_scenarios.sh
export KUBECONFIG=terraform/devsecops-lab-config
./scripts/attack_scenarios.sh          # aide
./scripts/attack_scenarios.sh S2       # credentials
./scripts/attack_scenarios.sh all
```

| ID | Scénario | Commandes types | Features IA visées |
|----|----------|-----------------|-------------------|
| S0 | Baseline | `ls`, `cat html`, `nginx -v` | score bas |
| S1 | Recon | `whoami`, `id`, `ps`, `env` | verbe, shell spawn |
| S2 | Credentials | `cat /etc/passwd`, `/proc/self/environ`, `.ssh` | `is_sensitive_file` |
| S3 | Package manager | `apt-get update` | `is_long_runtime`, package |
| S4 | Outbound port | `curl host:8080` | Falco rport + réseau |
| S5 | C2 IOC | `evil.com`, `malware.com` | `target_domain` |
| S6 | Exfil | `$(cat …)` pipe | `has_pipe`, subshell |
| S7 | Persistence | cron, `backdoor.sh` | keywords |
| S8 | Burst | 15× `whoami` | `event_count_5min` |

## Fuseau horaire

Falco envoie `time` en UTC (`Z`). Le modèle convertit en **Africa/Tunis** (UTC+1, pas de DST). `hour_of_day`, `is_weekend`, `is_off_hours` (08h–18h) et l'histogramme UBA utilisent l'heure **locale Tunis**, pas UTC. `timestamp_has_tz` indique si l'événement portait un offset. Variable : `LAB_TIMEZONE` (défaut `Africa/Tunis`).

Après changement de features : relancer `python src/train.py`.
