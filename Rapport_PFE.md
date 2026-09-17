# Prototype DevSecOps d’analyse comportementale et de remédiation sur Kubernetes

**Projet de Fin d’Études (PFE)**  
**Filière / établissement :** à compléter (le fichier `.env.example` mentionne un destinataire `@istic.ucar.tn`)  
**Auteur :** [Nom Prénom]  
**Encadrant :** [Nom]  
**Année :** 2025–2026  

**Avertissement méthodologique.** Ce document décrit uniquement ce qui est présent dans le dépôt `devsecops-ai-prototype` (code Python, Terraform, règles Falco, datasets, modèles pickle). Les sections Maven, image Docker applicative, cloud public et CI/CD sont marquées **non implémentées**. Aucune capture d’écran n’était versionnée dans le projet ; les figures renvoient vers `docs/captures/` (voir annexe A).

---

## Résumé

Ce travail conçoit et implémente un **laboratoire Kind** dans lequel les événements d’exécution captés par **Falco** (pilote eBPF) sont transmis par **Falcosidekick** à un service **Flask**. Celui-ci applique un moteur **hybride** : classifieur **Random Forest** (couche globale) et **UBA** (profils par UID + IsolationForest). Un score combiné déclenche, au-delà du seuil 70/100, une **quarantaine Cilium** (`label quarantine=true` + `CiliumNetworkPolicy` deny-all), le **scale** d’un replica sain, et éventuellement un **ticket Jira Cloud** et un **e-mail Gmail**. L’infrastructure est déclarée en **Terraform** (Kind, Helm Cilium 1.16, Falco, kube-prometheus-stack). Le collector n’est pas conteneurisé ; Grafana importe un dashboard JSON fourni.

**Mots-clés :** Kubernetes, Kind, Falco, Cilium, UBA, Random Forest, IsolationForest, Terraform, Prometheus.

## Abstract

This PFE implements a local Kind lab where Falco events are scored by a hybrid Random Forest + user-behaviour engine and, above a fixed threshold, a Cilium network quarantine is applied. Terraform provisions the cluster. There is no custom application Docker image, no Maven build, no managed cloud, and no CI/CD pipeline in the repository.

---

## Table des matières

1. Contexte et objectifs  
2. Besoins et exigences  
3. Architecture et conception  
4. Technologies et choix techniques  
5. Maven / Docker / DevOps / Cloud / CI-CD  
6. Implémentation  
7. Tests et validation  
8. Résultats  
9. Difficultés et solutions  
10. Conclusion et perspectives  
Annexes  

---

## 1. Contexte et objectifs

### 1.1 Contexte

Les plateformes Kubernetes exposent une surface d’exécution (processus, fichiers, réseau) que les règles statiques seules saturent d’alertes. Falco observe le noyau (ici **modern eBPF**) et émet des événements ; sans couche de **contexte utilisateur**, un `cat` métier et une exfiltration se ressemblent.

Le projet se place dans un **lab pédagogique**, pas dans un cluster de production managé. Le CNI par défaut de Kind est **désactivé** pour installer **Cilium**, afin de pouvoir appliquer une **NetworkPolicy L3/L7 Cilium** d’isolation.

### 1.2 Problématique

Comment enchaîner, de façon reproductible sur une machine locale : (1) télémétrie d’exécution, (2) score d’anomalie **global + comportemental**, (3) **isolation réseau** du pod incriminé **sans le détruire**, (4) notification optionnelle (Jira, e-mail) ?

### 1.3 Objectifs atteints (preuves dans le code)

| Objectif | Preuve |
|----------|--------|
| Cluster lab reproductible | `terraform/cluster.tf`, `cilium.tf`, `falco.tf`, `demo.tf`, `monitoring.tf` |
| Règles Falco custom | `terraform/falco_rules.local.yaml` chargé par Helm dans `falco.tf` |
| Scoring hybride | `src/models/engine.py`, `global_model.py`, `uba_model.py` |
| Webhook temps réel | `src/collector.py` route `POST /events` |
| Quarantaine | `src/core/remediation.py` + `terraform/quarantine-policy.tf` |
| Ticketing / mail optionnels | `src/core/jira_ticketing.py`, `src/core/alerting.py` |
| Observabilité IA | métriques `prometheus_client` + `config/grafana_dashboard.json` |
| Démo unique | `scripts/demo_attaque.sh` |

### 1.4 Objectifs hors périmètre (non implémentés)

- Pipeline CI/CD (GitHub Actions, GitLab CI, Jenkins, Maven)  
- Dockerfile / image du collector / docker-compose applicatif  
- Cluster cloud (EKS, GKE, AKS, OpenStack)  
- UI Falcosidekick (explicitement `falcosidekick.webui.enabled = false`)  
- Remédiation au-delà du label + scale (pas de kill, pas de rebuild, pas de rotation de secrets)  
- Scénario de test de la règle Falco **inbound**  
- Tests unitaires automatisés (`pytest` absent du dépôt)

---

## 2. Besoins et exigences

Les exigences ci-dessous sont **rétro-extraites** du comportement réel, pas d’un cahier des charges externe versionné.

### 2.1 Fonctionnelles

- **RF-1** Réception JSON Falcosidekick et ignore des événements **sans nom de pod** (`event_scope == node`).  
- **RF-2** Calcul d’un score dans [0, 100] et d’un statut : NORMAL &lt; 20, SUSPECT ≥ 20, MODÉRÉ ≥ 45, CRITIQUE ≥ 70 (`engine.py`).  
- **RF-3** Si score ≥ 70 : label `quarantine=true`, annotations `devsecops.ai/*`, scale Deployment à (pods déjà isolés + 1).  
- **RF-4** Si déjà isolé : pas de nouveau Jira/mail.  
- **RF-5** Journalisation CSV 22 colonnes (`FALCO_CSV_COLUMNS` dans `settings.py`).  
- **RF-6** Jira et Gmail **désactivés silencieusement** si variables d’environnement absentes.

### 2.2 Non fonctionnelles

- Lab local : Kind, une machine hôte, webhook joignable depuis les conteneurs (`collector_host`, défaut `172.17.0.1`).  
- Fuseau métier **Africa/Tunis** (UTC+1, pas de DST) pour l’UBA.  
- Horaires 8 h–18 h (`BUSINESS_HOUR_START` / `END`).  
- Secrets hors Git (`.gitignore` ignore `.env`).

### 2.3 Contraintes de démo

Une seule attaque sûre : lecture de `/proc/self/environ`, `apt-get --version` (pas d’install), `curl` timeout 3 s vers un IOC de lab `evil.com:8080`. Alignement volontaire avec les **conditions Falco déployées** (pas `/etc/passwd` pour la règle SSH/PEM).

---

## 3. Architecture et conception

### 3.1 Vue d’ensemble

```
terraform apply
    → Kind (control-plane + worker), pod CIDR 10.244.0.0/16, sans CNI par défaut
    → Helm Cilium 1.16.0 (kube-system)
    → Helm Falco + Falcosidekick (ns falco) → HTTP POST hôte:5002/events
    → Helm kube-prometheus-stack (ns monitoring)
    → Deployment nginx-demo (ns demo-app)
    → CiliumNetworkPolicy quarantine-policy (sélecteur quarantine=true)

Hôte :
    python src/collector.py
        → HybridEngine.predict
        → si score ≥ 70 : kubectl label + scale
        → Jira REST / SMTP Gmail (optionnel)
        → append datasets/falco_events_dataset_v2.csv
        → métriques :8000
```

**Figure 1 — Architecture logique du prototype (à capturer ou redessiner).**  
Fichier attendu : `docs/captures/01-architecture-live.png`.  
La figure doit montrer que le collector **n’est pas** un Pod : Falcosidekick sort du cluster vers l’IP hôte.

### 3.2 Découpage logiciel

| Module | Rôle |
|--------|------|
| `src/collector.py` | Orchestration HTTP + Prometheus + CSV |
| `src/models/engine.py` | Arbitrage RF / UBA |
| `src/models/global_model.py` | Features, labels d’entraînement, RandomForest |
| `src/models/uba_model.py` | Profils JSON + IsolationForest par UID |
| `src/core/features.py` | Verbe, domaine, burst 5 min, vecteur `FEATURE_COLS` |
| `src/core/time_features.py` | Conversion TZ, durée Falco ns/ms |
| `src/core/iocs_loader.py` | Charge `src/config/iocs.json` |
| `src/core/remediation.py` | kubectl via `KUBECONFIG` |
| `src/core/jira_ticketing.py` | API REST v3, dédoublonnage JQL |
| `src/core/alerting.py` | SMTP Gmail STARTTLS 587 |
| `src/core/csv_io.py` | Réparation 21 vs 22 colonnes |
| `src/run_train.py` | Fusion CSV live + synthétique, `engine.train` |
| `src/generate_smart_testdata.py` | Génération CSV synthétique |
| `src/generate_personas.py` | Rappelle le générateur puis ajoute uid 472 et extra admin |
| `src/demo_decision_table.py` | Cas d’arbitrage hors cluster |

### 3.3 Conception du score

Formule de base :

\[
S = 0{,}35 \cdot S_{\mathrm{RF}} + 0{,}65 \cdot S_{\mathrm{UBA}}
\]

Règles **ensuite** appliquées (ordre du code) :

1. Recon bénin : UBA ≤ 5, verbe dans `recon_verbs`, pas d’IOC fort → plafond bas.  
2. Comportement habituel : UBA &lt; 22, heures ouvrées, burst &lt; 10 → plafond `0,40 · S_RF`.  
3. UBA élevé sans IOC fichier/réseau et burst &lt; 15 → plafond 55.  
4. Fichier sensible **et** (nuit ou burst ≥ 15) **et** UBA ≥ 30 → plancher 75.  
5. Domaine `external_malicious` **et** (sensible ou nuit ou burst ≥ 10) → plancher 85.

Un IOC « fort » est : chemin sensible (`is_sensitive_target`) **ou** domaine malveillant listé.

### 3.4 Conception de la quarantaine

La politique Cilium ne sélectionne **que** les endpoints `quarantine=true`. Ingress et egress sont niés vers/depuis l’entité `all`. Le pod **reste Running** : choix explicite dans les logs (`pas de delete`). Un replica supplémentaire évite de couper le service nginx du Deployment.

**Limite :** un pod autonome (sans Deployment) n’est pas scalé ; message d’erreur métier dans `_ensure_healthy_replica`.

---

## 4. Technologies et choix techniques

| Technologie | Version / usage dans le dépôt | Justification observée |
|-------------|-------------------------------|-------------------------|
| Terraform | providers Kind `tehcyx/kind` ~> 0.5, kubernetes ~> 2.27, helm ~> 2.13 | Infra as code du lab |
| Kind | cluster `devsecops-lab` | Kubernetes local, pas de cloud |
| Cilium | chart **1.16.0** | NetworkPolicy d’isolation |
| Falco | chart officiel, `driver.kind = modern_ebpf` | Pas de module kernel compilé |
| Falcosidekick | webhook only | Moins de composants (pas Redis/UI) |
| Python ≥ 3.10 (README) | Flask, pandas, numpy, scikit-learn, prometheus-client | Collector + ML |
| RandomForestClassifier | `n_estimators=80`, `max_depth=4`, `min_samples_split=25`, `min_samples_leaf=12`, `class_weight=balanced` | Commentaire code : éviter un AUC « parfait » qui recopie Falco |
| IsolationForest | `contamination=0.15` si ≥ 10 événements / UID | Anomalie non supervisée intra-utilisateur |
| Prometheus / Grafana | kube-prometheus-stack, NodePort 30090 / 30030 | Scraping du collector |
| Jira Cloud REST | Basic auth e-mail + API token | Tickets `SEC` par défaut |
| SMTP Gmail | mot de passe d’application | Alerte humaine |

**Non utilisés :** Maven/Java, Kubernetes Operators custom, service mesh Istio, Falco Talon, OPA/Gatekeeper, Vault.

---

## 5. Maven / Docker / DevOps / Cloud / CI-CD

### 5.1 Maven

**Non implémenté.** Aucun `pom.xml`. La pile applicative est Python.

### 5.2 Docker

**Partiel, indirect.** Kind exécute les nœuds Kubernetes comme conteneurs Docker. L’application cible est l’image publique **`nginx:latest`** (`terraform/demo.tf`). **Aucun Dockerfile** du collector, **aucun docker-compose** du moteur IA.

### 5.3 DevOps (implémenté)

- Provisioning : `terraform init && terraform apply`  
- Git : dépôt avec `.gitignore` (tfstate, kubeconfig, `.env`)  
- Observabilité : Prometheus scrape + dashboard Grafana JSON  
- IaC Helm via provider Terraform  

**Point dur connu :** `monitoring.tf` scrape **`192.168.41.128:8000` en dur**. Les variables `collector_host` / `collector_metrics_port` existent pour Falco mais **ne sont pas** utilisées dans ce scrape. Grafana peut rester vide si l’IP de la machine a changé.

### 5.4 Cloud

**Non implémenté** comme plateforme d’exécution du cluster. Jira Cloud et Gmail sont des **SaaS de notification**, pas l’hébergement Kubernetes.

### 5.5 CI/CD

**Non implémenté.** Pas de workflow d’intégration, pas de tests dans un pipeline, pas de scan d’image automatisé.

---

## 6. Implémentation

### 6.1 Infrastructure Terraform

- **Nœuds :** 1 control-plane + 1 worker.  
- **Kubeconfig :** `kubeconfig_path = ${path.module}/devsecops-lab-config`.  
- **Falco customRules :** contenu fichier local injecté dans Helm.  
- **Sorties :** URL webhook, NodePorts Grafana/Prometheus (`terraform/outputs.tf`).  
- **Grafana lab :** utilisateur `admin` / mot de passe `admin` (inacceptable en production ; acceptable en Kind).  
- **Alertmanager :** toujours `enabled = true` dans `monitoring.tf` ; le produit n’y définit **pas** de routes d’alerte métier (les alertes utiles sont Jira + mail).

**Figure 2 — Inventaire des Pods après `terraform apply`.**  
`docs/captures/02-kubectl-get-pods.png` — Namespaces `kube-system` (Cilium), `falco`, `monitoring`, `demo-app`.

### 6.2 Règles Falco réellement déployées

Fichier unique de vérité : `terraform/falco_rules.local.yaml`.

| Règle | Condition (résumé) | Priorité |
|-------|-------------------|----------|
| Suspicious outbound connection | `outbound` + conteneur + `rport` ∉ {80,443,53} | WARNING |
| Unexpected inbound connection on non-standard port | `accept` + `lport` ∉ {80,443,53} | WARNING |
| Sensitive file access outside shadow | lecture `/etc/ssh`, `/root/.ssh`, `*.pem` | CRITICAL |
| Sensitive environment variable credential access | `/proc/self/environ` ou `/proc/*/environ` | WARNING |
| Unexpected package manager execution | apt/yum/dnf/apk/pip | WARNING |
| Unexpected process spawned in application container | bash/sh/zsh/nc/ncat/curl/wget | WARNING |
| Baseline normal activity demo-app | tout `spawned_process` dans `k8s.ns.name = demo-app` | INFORMATIONAL |

Les champs `%evt.duration` et `%proc.duration` sont dans l’`output` pour alimenter `output_fields` côté Falcosidekick.

**Figure 3 — Logs Falco après exécution de la démo.**  
`docs/captures/03-falco-logs.png` — Vérifier la présence des noms de règles ci-dessus, pas d’une règle inventée.

### 6.3 Collector Flask

- Bind `0.0.0.0:5002`, métriques `start_http_server(8000)`.  
- Mapping JSON → vecteur événement (`user.name`, `proc.cmdline`, `k8s.pod.name`, …).  
- Compteurs : `devsecops_falco_events_total`, `devsecops_ai_alerts_total{severity}`, `devsecops_remediations_total{status}`, `devsecops_jira_tickets_total{status}`.  
- Jauges : `devsecops_ai_anomaly_score` (labels user, pod, rule).

**Figure 4 — Logs du collector (score et statut).**  
`docs/captures/04-collector-logs.png`.

### 6.4 Couche 1 — Random Forest

**Étiquetage (`label_is_anomaly`) :**  
- 0 si règle dans `NOISE_RULES` (dont baseline demo-app, Contact K8S API, Drop and execute new binary, Directory traversal).  
- Pour outbound : 1 seulement si domaine `external_malicious` ou `external_unknown`.  
- 1 si règle dans `ANOMALY_RULES`.

**Vecteur (`FEATURE_COLS`) :** heure, jour, week-end, hors horaires, présence TZ, longueur/args commande, durée ms, runtime long (≥ 3 s), pipe, redirect, `$(`, shell spawn, indirection, burst 5 min, verbe encodé (`LabelEncoder`).

Split temporel **75 % / 25 %** (pas de k-fold). Métriques affichées à l’entraînement : classification_report, ROC-AUC si les deux classes existent, matrice de confusion, importances.

Artefacts : `models/layer1_global.pkl`, `layer1_encoders.pkl`, `layer1_feature_cols.pkl`.

### 6.5 Couche 2 — UBA

Pour chaque `user_uid` avec ≥ 3 événements : histogramme horaire (sur le trafic non « évident » C2/privesc), top verbes, domaines, taux fichiers sensibles, stats de longueur.

Si ≥ 10 événements : IsolationForest sur  
`(hour, day_of_week, command_length, is_sensitive_file, has_pipe, has_redirect, is_off_hours, command_duration_ms)`  
après `StandardScaler`.

Score additif plafonné à 100 (heures, verbe inédit +30, domaine malveillant +50, sensible rare +40, burst, durée, IF +30). Utilisateur inconnu : **50** et raison « Utilisateur inconnu ».

Profils présents : `uba_0`, `1000`, `1001`, `472`, `999`, plus `uba_2000.json` et `uba_65534.json` **sans** `uba_if_*.pkl` correspondant (résidus de datasets live, UID Kubernetes `65534` = nobody).

### 6.6 IOC

`src/config/iocs.json` : domaines lab (`evil.com`, …), chemins sensibles (inclut `/etc/passwd` **pour l’IA**, alors que Falco custom ne matche pas `/etc/passwd` — écart volontaire règles vs features), verbes recon/privesc/package/réseau, mapping rôles → UID.

### 6.7 Données

- Synthétique `falco_events_enriched.csv` : **1155** lignes ; users admin 372, dev 248, root 215, python 200, bot 120 ; UIDs 1000, 1001, 0, 472, 999.  
- Live `falco_events_dataset_v2.csv` : **2810** lignes ; mixte règles Falco **stock** et custom (beaucoup de `Contact K8S API Server From Container`, outbound, `Drop and execute…`).  
- `run_train.py` concatène les deux, filtre pods vides/`unknown`, normalise `user_uid`.

`generate_personas.py` n’est **pas** dans le chemin runtime : il régénère le CSV synthétique (et rappelle déjà `generate_smart_testdata.main()`). Inutile le jour J si les pickle existent.

### 6.8 Intégrations optionnelles

Jira : recherche ticket ouvert `labels = auto-quarantine` + résumé contenant le nom du pod ; sinon `POST /rest/api/3/issue` (description ADF).  
Gmail : ignore si `GMAIL_SENDER`, `GMAIL_RECEIVER` ou `GMAIL_APP_PASSWORD` manquant.

---

## 7. Tests et validation

### 7.1 Ce qui existe

1. **Entraînement supervisé interne** (`run_train.py`) : split 75/25, rapport sklearn.  
2. **Table de décision** (`demo_decision_table.py`) : 8 cas (dev `ls`, shadow 14 h vs 02 h vs burst, admin shadow, service python vs bash vs C2). Ce n’est **pas** un test d’assertion (`assert`) ; c’est une **validation visuelle**.  
3. **Scénario d’intégration lab** : `scripts/demo_attaque.sh` + commandes manuelles du `Guide_Utilisation.md`.  
4. **Test e-mail manuel** : `python -m` / `if __name__` dans `alerting.py`.

**Figure 5 — Exécution du script de démo.**  
`docs/captures/05-demo-attaque.png`.

**Figure 9 — Sortie de la table de décision.**  
`docs/captures/09-decision-table.png`.

**Figure 12 — Métriques Random Forest à l’entraînement.**  
`docs/captures/12-run-train.png` — Recopier ROC-AUC et matrice de confusion **tels qu’affichés**, sans inventer un chiffre.

### 7.2 Ce qui n’existe pas

- Suite `pytest` / couverture  
- Tests d’intégration CI  
- Mesure systématique de faux positifs sur S0–S8 (l’ancien script multi-scénarios a été retiré)  
- Preuve automatisée que le score démo est toujours ≥ 70 en heures ouvrées (l’arbitrage peut caper sans IOC + burst)

### 7.3 Procédure de validation live recommandée

```text
1. Cluster + collector UP
2. kubectl get pods -n demo-app --show-labels   (pas de quarantine)
3. ./scripts/demo_attaque.sh
4. Logs Falco + logs collector
5. Labels quarantine=true et replicas Deployment ≥ 2 si score ≥ 70
6. Grafana : compteurs d’alertes / remédiations
7. Jira / mail seulement si .env renseigné
```

**Figure 6 — Labels après quarantaine.**  
`docs/captures/06-quarantine-labels.png`.

**Figure 7 — Extrait YAML de `quarantine-policy`.**  
`docs/captures/07-cilium-policy.png`.

**Figure 8 — Dashboard Grafana.**  
`docs/captures/08-grafana-dashboard.png` — Panneaux : Alertes Critiques IA, Quarantaines Cilium, Tickets Jira, Événements Falco, score par utilisateur (seuils 45 / 70 dans le JSON).

**Figures 10 et 11 — Jira et Gmail.**  
Uniquement si configurés ; sinon indiquer dans le rapport « non démontré — variables absentes ».

---

## 8. Résultats

Les résultats **chiffrés d’AUC** ne sont pas figés dans Git (sortie console de `run_train.py`). Le rapport de soutenance doit coller la **figure 12**.

Résultats **structurels** démontrables :

- Chaîne bout-en-bout Kind → Falco → Flask → Cilium **codée et déployable**.  
- Dualité règles Falco / features IA documentée (ex. `/etc/passwd` côté IOC, pas dans la règle SSH/PEM).  
- UBA différencie les UID 1000 (admin, shadow parfois « normal ») et 1001 / 472 (service).  
- Remédiation **non destructive**.  
- Notifications **best-effort**.

Limites empiriques du CSV live : forte proportion de règles Falco par défaut, étiquetées bruit pour le RF ; le modèle global apprend surtout les règles custom + outbound « externe ».

---

## 9. Difficultés et solutions

| Difficulté | Manifestation dans le code / l’infra | Solution retenue |
|------------|--------------------------------------|------------------|
| Falco UTC vs horaires Tunis | `time` en `Z` | `to_lab_local` + `LAB_TIMEZONE` |
| Falco ≠ attaque | Baseline et bruit K8s | `NOISE_RULES`, RF peu profond |
| Faux positifs métier | Admin lit shadow | UBA `sensitive_rate` + arbitrage plafond 55 |
| Webhook hors cluster | Pods Kind ≠ localhost | `collector_host` (docker0) |
| CSV colonnes 21/22 | Historique | `csv_io.repair_falco_csv` |
| Doublons Jira | Burst d’événements | Réutilisation ticket ouvert |
| Isolation trop brutale | Delete pod | Label + CNP + scale |
| Image nginx sans `curl` | Outbound non tiré | `|| true` + `apt-get --version` + environ |
| Scrape Prometheus IP fixe | Grafana vide | À corriger vers `var.collector_host` (fichier parfois non inscriptible) |
| Événements nœud | Bruit hôte | Ignore si pas de pod |

---

## 10. Conclusion et perspectives

### 10.1 Conclusion

Le prototype réalise une **boucle DevSecOps courte** sur un cluster Kind : détection eBPF, score hybride RF+UBA, isolation Cilium, observabilité Prometheus, ticketing optionnel. Il est honnête sur ses limites : lab local, seuil fixe 70, pas de CI/CD, pas d’image custom, pas de levée automatique de quarantaine.

### 10.2 Perspectives (non faites)

- Corriger le scrape Prometheus (variable Terraform).  
- Tests unitaires du moteur d’arbitrage.  
- Conteneuriser le collector (Service Kubernetes interne, plus de `172.17.0.1`).  
- CI : `terraform validate` + `run_train.py` hors cluster.  
- Après quarantaine « prod » : forensique, rotation de secrets, rebuild d’image, décision humaine de lever le label.  
- Démo inbound **seulement** si un Service NodePort non standard est ajouté.  
- Recalibrer les IOC (`pastebin.com` comme malveillant est discutable).

---

## Références techniques (outils du dépôt, pas une revue de littérature fictive)

- Code source du dépôt : `src/`, `terraform/`, `scripts/demo_attaque.sh`  
- Documentation projet : `README.md`, `Guide_Utilisation.md`  
- Falco / Falcosidekick / Cilium / Kind / scikit-learn : documentations officielles des versions utilisées au moment du `terraform apply` local  

Compléter ici les normes académiques de l’établissement (IEEE/APA) **uniquement** pour les documents réellement lus.

---

## Annexe A — Captures manquantes

**Aucune image n’était dans le Git.** Liste opérationnelle : `docs/captures/README.md`.

Légendes à copier sous chaque PNG une fois collé :

- **Figure 1.** Architecture du prototype : Terraform/Kind, Falco, collector hôte, Cilium, Grafana.  
- **Figure 2.** État du cluster (tous namespaces).  
- **Figure 3.** Preuve que les règles custom se déclenchent.  
- **Figure 4.** Preuve du score IA temps réel.  
- **Figure 5.** Reproductibilité de la démo unique.  
- **Figure 6.** Effet Kubernetes de la remédiation (label).  
- **Figure 7.** Politique deny-all Cilium.  
- **Figure 8.** Corrélation métriques métier (alertes, quarantaines, tickets).  
- **Figure 9.** Validation hors bande de l’arbitrage UBA.  
- **Figure 10.** Ticket incident (si SaaS configuré).  
- **Figure 11.** Notification e-mail (si SaaS configuré).  
- **Figure 12.** Qualité du classifieur global sur le split d’entraînement.

## Annexe B — Ports et identifiants de lab

| Service | Port / accès |
|---------|----------------|
| Collector webhook | 5002 |
| Métriques | 8000 |
| Grafana NodePort | 30030 (`admin`/`admin`) |
| Prometheus NodePort | 30090 |

## Annexe C — Glossaire

**UBA :** User Behaviour Analytics, ici profil par UID Linux observé dans Falco.  
**IOC :** indicateur de compromission listé dans `iocs.json` (lab).  
**Quarantaine :** isolation réseau Cilium, pas destruction du Pod.
