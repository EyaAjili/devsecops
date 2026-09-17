# Guide d’utilisation (soutenance)

## Prérequis

Docker, Kind, Terraform ≥ 1.5, kubectl, Python ≥ 3.10.

## 1. Cluster

```bash
cd terraform
terraform init
terraform apply
export KUBECONFIG=$PWD/devsecops-lab-config
kubectl get nodes
kubectl get pods -A
```

Si Falcosidekick n’atteint pas le collector, passer l’IP hôte :

```bash
terraform apply -var='collector_host=VOTRE_IP'
```

Sur Linux, le défaut `172.17.0.1` est souvent le pont Docker.

## 2. Modèle IA puis collector

```bash
cd src
pip install -r requirements.txt
python generate_smart_testdata.py
python generate_personas.py
python run_train.py
```

Jira / Gmail sont **optionnels**. Sans eux, scoring + Cilium fonctionnent quand même.

```bash
# optionnel : copier .env.example puis exporter les variables
export KUBECONFIG=../terraform/devsecops-lab-config
python collector.py
```

Laisser ce terminal ouvert. Webhook `:5002`, métriques `:8000`.

Grafana (login `admin` / `admin`) :

```bash
kubectl -n monitoring port-forward svc/kube-prometheus-stack-grafana 3000:80
```

Importer `config/grafana_dashboard.json` si le dashboard n’est pas déjà là.

## 3. Commandes manuelles devant l’encadrant

Dans un **nouveau** terminal (cluster + collector déjà lancés) :

```bash
export KUBECONFIG=/chemin/vers/devsecops-ai-prototype/terraform/devsecops-lab-config

kubectl get pods -n demo-app
POD=$(kubectl get pods -n demo-app -l app=nginx-demo -o jsonpath='{.items[0].metadata.name}')
echo "$POD"
```

**Démo unique (sûre)** — lecture de l’environnement du conteneur, `apt-get --version` (pas d’install), `curl` vers un IOC de lab sur le port **8080** (timeout 3 s). Pas de malware, pas de cron, pas d’écriture persistante. `|| true` : si `curl` n’est pas dans l’image nginx, le reste de la démo continue.

```bash
kubectl exec -n demo-app "$POD" -- sh -c 'cat /proc/self/environ; apt-get --version; curl -s --max-time 3 http://evil.com:8080/ || true'
```

Pourquoi ces commandes (règles **réelles** dans `terraform/falco_rules.local.yaml`) :

| Action | Règle Falco |
|--------|-------------|
| `sh` / `curl` dans nginx | `Unexpected process spawned in application container` |
| tout process dans `demo-app` | `Baseline normal activity demo-app` |
| `cat /proc/self/environ` | `Sensitive environment variable credential access` |
| `apt-get` | `Unexpected package manager execution` |
| `curl` port **8080** | `Suspicious outbound connection` (seulement si `curl` existe) |

Côté IA, `evil.com` est dans `src/config/iocs.json` et `/proc/self/environ` est un chemin sensible : le moteur peut monter le score (souvent ≥ 70) puis poser `quarantine=true`.

**Vérifications immédiates :**

```bash
# logs Falco
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=40

# quarantaine Cilium (label)
kubectl get pods -n demo-app --show-labels

# replica (le code scale N+1 si isolation)
kubectl get deploy nginx-demo -n demo-app
```

Dans le terminal du collector : ligne `Event | …` et éventuellement `REMEDIATION`.

**Nettoyage après la démo :**

```bash
kubectl label pod -n demo-app -l app=nginx-demo quarantine-
kubectl scale deploy nginx-demo -n demo-app --replicas=1
```

## 4. Le même scénario en un script

```bash
export KUBECONFIG=terraform/devsecops-lab-config
chmod +x scripts/demo_attaque.sh
./scripts/demo_attaque.sh
```

### Ligne par ligne (`scripts/demo_attaque.sh`)

1. `#!/usr/bin/env bash` — interpréteur bash.
2. Commentaires : une seule démo, alignée sur les règles Terraform.
3. `set -euo pipefail` — arrêt si une commande échoue, variables non définies interdites.
4. `NAMESPACE="demo-app"` — namespace du nginx de lab.
5. `LABEL="app=nginx-demo"` — sélecteur du Deployment.
6. `echo "== 1. …"` — message pour la soutenance.
7. `POD=$(kubectl get pods … jsonpath=…)` — nom réel du pod (`nginx-demo-xxxxx`).
8. `if [ -z "$POD" ]` — arrêt clair si le cluster n’est pas là.
9. `echo "Pod : $POD"` — afficher le nom à l’encadrant.
10. `echo "== 2. …"` — annonce de la commande.
11. `kubectl exec … sh -c 'cat /proc/self/environ; apt-get --version; curl … || true'` — actions Falco/IA ; `|| true` si `curl` est absent ou si le DNS timeout.
12. `echo "== 3. …"` — annonce de la vérif Kubernetes.
13. `kubectl get pods … --show-labels` — voir `quarantine=true` si remédiation.
14. `echo "Fin. …"` — renvoyer vers les logs Flask.

## 5. Table de décision IA sans cluster (optionnel)

```bash
cd src
python demo_decision_table.py
```

## Fuseau

Falco envoie l’heure en UTC. L’UBA utilise `LAB_TIMEZONE` (défaut `Africa/Tunis`). Après un changement de features : `python src/run_train.py`.
