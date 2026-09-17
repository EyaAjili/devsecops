# PFE Technical Report — Study and Defense Document

**Repository:** `devsecops-ai-prototype`  
**Rule:** this file documents only what exists in the tree. If it is not in the repo, it is marked **NOT CURRENTLY IMPLEMENTED** or **Not verified in the current repository.**

Status labels used everywhere:

| Label | Meaning |
|-------|---------|
| **CURRENTLY IMPLEMENTED** | Present in source / Terraform / datasets / models |
| **IMPLEMENTED BUT LIMITED** | Present, with a documented weakness |
| **IMPROVEMENT APPLIED** | Simplification already in the repo (single demo script, `kubeconfig_path`, dead Falco copies removed) |
| **OPTIONAL PRODUCTION IMPROVEMENT** | Suggestion only — do not present as done |
| **NOT CURRENTLY IMPLEMENTED** | Absent (no Dockerfile, no CI/CD, no Maven, no Falcosidekick UI, no pytest) |

Leftover bytecode under `src/__pycache__/train.py`, `predict_cli.py`, `hybrid_engine.py` is **not** active source. The live ML engine is `src/models/engine.py`.

---

# 1. Project Overview

This project is a **local Kind laboratory** that connects:

1. **Runtime detection** — Falco with the **modern eBPF** driver and custom rules in `terraform/falco_rules.local.yaml`.
2. **Hybrid scoring** — Random Forest (global classification) + UBA (per-UID profile + Isolation Forest) in `src/models/`.
3. **Automatic containment** — Kubernetes label `quarantine=true` plus a Cilium deny-all policy (`terraform/quarantine-policy.tf`), invoked from Python via `kubectl` (`src/core/remediation.py`).
4. **Optional human alerting** — Jira Cloud REST and Gmail SMTP if environment variables are set.
5. **Observability** — Prometheus metrics from the Flask collector and a Grafana dashboard JSON.

The AI process **does not run inside Kubernetes**. Falcosidekick POSTs to the **host** (`collector_host:5002`). That is the real architecture, not a “cluster-native SOAR platform”.

---

# 2. Problem Statement

Falco can emit many events: every `sh` in `demo-app` matches both a **baseline** rule and often **Unexpected process spawned**. A developer `ls` and a credential theft can share the same Falco rule name.

**Problem:** rules see *what happened*; they do not know *whether this UID usually does it at this hour*.

**What this repo adds:** a second opinion (RF + UBA + explicit arbitration in `engine.py`) and, above score **70**, network isolation **without deleting the pod**.

**What this repo does not solve:** production HA, CI security gates, human-labeled ground truth, inbound-attack demo, collector authentication.

---

# 3. Objectives

| Objective | Status | Evidence |
|-----------|--------|----------|
| Reproducible K8s lab | CURRENTLY IMPLEMENTED | `terraform/*.tf` |
| Runtime events from containers | CURRENTLY IMPLEMENTED | Falco Helm + custom YAML |
| Score events with RF + UBA | CURRENTLY IMPLEMENTED | `engine.py`, pickles in `models/` |
| Quarantine via Cilium | CURRENTLY IMPLEMENTED | `remediation.py` + CNP |
| Keep process for forensics | CURRENTLY IMPLEMENTED | comment and code: no delete; annotations |
| Scale a healthy replica | CURRENTLY IMPLEMENTED | `_ensure_healthy_replica` |
| Tickets / email | IMPLEMENTED BUT LIMITED | skipped if env empty |
| Metrics dashboard | IMPLEMENTED BUT LIMITED | scrape IP hardcoded `192.168.41.128:8000` |
| Custom collector image / CI | NOT CURRENTLY IMPLEMENTED | no Dockerfile, no `.github/workflows` |

---

# 4. System Architecture

## 4.1 Layers (as they actually exist)

### Infrastructure

- **Host:** Linux machine with Docker (required by Kind). Not described further in code.
- **Docker:** runtime for Kind node containers; also pulls `nginx:latest`. **No project Dockerfile.**
- **Kubernetes:** Kind cluster `devsecops-lab`, 1 control-plane + 1 worker, default CNI **disabled**, pod CIDR `10.244.0.0/16` — `terraform/cluster.tf`.
- **Terraform:** Kind + Kubernetes + Helm providers — `terraform/versions.tf`.
- **Networking:** Cilium 1.16.0 as CNI — `terraform/cilium.tf` (`k8sServiceHost=devsecops-lab-control-plane`, port `6443`).
- **Namespaces:** `demo-app`, `falco`, `monitoring`, plus `kube-system` for Cilium.
- **Storage:** no PVC in Terraform. Models/CSV live on the **host filesystem**.
- **Secrets:** `.env` gitignored; collector reads **OS environment**, not a K8s Secret. Grafana password `admin` in `monitoring.tf`.

### Application

- Workload: Deployment `nginx-demo`, 1 replica, image `nginx:latest`, container port 80 — `terraform/demo.tf`.
- **No** Kubernetes Service object in the repo for nginx (CNP and exec do not need it).
- Collector: Flask on host `:5002`, Prometheus client `:8000` — `src/collector.py`.

### Security

- Falco DaemonSet via Helm chart; driver `modern_ebpf`.
- Custom rules file injected as Helm `customRules`.
- Falcosidekick webhook, **WebUI disabled**.
- Chart **default rules** also fire (visible in live CSV).

### AI/ML

- Train: `src/run_train.py`.
- Infer: `HybridEngine.predict` from collector.
- Artifacts: `models/layer1_*.pkl`, `models/uba_if_<uid>.pkl`, `profiles/uba_<uid>.json`.

### Observability

- `prometheus_client` counters/gauges in collector.
- kube-prometheus-stack Helm; Grafana NodePort 30030; Prometheus 30090.
- Dashboard file `config/grafana_dashboard.json` (import; not auto-provisioned in Terraform).

### Response

- Decision: Python threshold 70.
- Notification: Jira + Gmail optional.
- Containment: label + Cilium deny-all.
- Evidence: pod **not deleted**; annotations `devsecops.ai/quarantined-at|score|rule`; CSV append.

## 4.2 Real control/data flow

```text
terraform apply
    → Kind nodes (Docker) + Cilium + Falco + nginx-demo + CNP + kube-prometheus-stack

kubectl exec / app syscalls in nginx pod
    → eBPF (Falco modern_ebpf)
    → Falco rule (custom YAML and/or chart defaults)
    → Falcosidekick JSON HTTP POST
         http://<collector_host>:5002/events     [default 172.17.0.1]

collector.py
    → drop if no k8s.pod.name
    → HybridEngine.predict (RF + UBA + arbitration)
    → Prometheus gauges/counters
    → if score ≥ 70: kubectl label/annotate/scale
    → Jira / Gmail if configured
    → append datasets/falco_events_dataset_v2.csv

Prometheus scrapes 192.168.41.128:8000   [HARDCODED in monitoring.tf]
Grafana displays dashboard JSON (manual import)
```

This is **not** “logs file → batch Spark”. It is **HTTP webhook, in-process ML, out-of-cluster kubectl**.

---

# 5. Complete End-to-End Workflow

### Stage 1 — Provision cluster

| | |
|--|--|
| **Input** | Terraform code, Docker daemon |
| **Processing** | Kind cluster, Helm Cilium/Falco/kube-prometheus-stack, k8s resources |
| **Output** | API server, kubeconfig `terraform/devsecops-lab-config` |
| **Implementation** | `terraform/cluster.tf` and siblings |
| **Technology** | Terraform, Kind, Helm, Kubernetes |
| **Communication** | kubeconfig for later kubectl |
| **Verification** | `kubectl get nodes`, `kubectl get pods -A` — **manual**; no automated test in repo |

### Stage 2 — Workload runs

| | |
|--|--|
| **Input** | `nginx:latest` |
| **Output** | Pod `nginx-demo-xxxxx` in `demo-app` |
| **File** | `terraform/demo.tf` |
| **Verification** | `kubectl get pods -n demo-app` |

### Stage 3 — Syscall → Falco

| | |
|--|--|
| **Input** | exec/open/connect in the container |
| **Processing** | eBPF programs (Falco driver); rule engine |
| **Output** | Alert: `rule`, `priority`, `time`, `output_fields` |
| **Files** | `terraform/falco.tf`, `terraform/falco_rules.local.yaml` |
| **Example** | `cat /proc/self/environ` → rule `Sensitive environment variable credential access` if `open_read` on that path |
| **Verification** | `kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=40` |

### Stage 4 — Falcosidekick → collector

| | |
|--|--|
| **Input** | Falco alert |
| **Output** | HTTP JSON POST `/events` |
| **Config** | `falcosidekick.config.webhook.address` |
| **Failure mode** | Wrong `collector_host` → no events in Flask |
| **Verification** | Flask prints `[+] Event \| <rule>` |

### Stage 5 — Parse

**File:** `src/collector.py` `receive_falco_event`.

Maps:

- `data["time"]` → `timestamp`
- `output_fields["user.name"]`, `user.uid`, `proc.cmdline`, `proc.name`, `proc.pname`, `fd.name`, `k8s.pod.name`
- durations via `parse_duration_ms(proc.duration, evt.duration)`

If `k8s.pod.name` missing → HTTP 200 `ignored` (host/node noise).

### Stage 6 — ML

**File:** `src/models/engine.py`. See sections 16–21.

### Stage 7 — Decision / metrics / CSV

Counters: critical ≥70, moderate ≥45, suspect ≥20.  
CSV row always appended for pod-scoped events (even if score is low).

**Limitation:** `df_history` loaded **once at process start**. New CSV rows are **not** merged into memory, so `event_count_5min` during a live session mostly sees **pre-start** history.

### Stage 8 — Containment

**File:** `src/core/remediation.py`.  
Requires `status == "🚨 ANOMALIE CRITIQUE"` **and** `score >= 70`.  
`kubectl` uses `KUBECONFIG` from `settings.py`.

### Stage 9 — Observe

Prometheus scrape (IP may be stale). Grafana panels in `config/grafana_dashboard.json`.

---

# 6. Infrastructure

**CURRENTLY IMPLEMENTED**

Kind is Kubernetes-in-Docker: two containers act as nodes. Control-plane holds the API; worker runs workloads (and Falco as a chart typically schedules a DaemonSet on nodes).

**Why disable default CNI?** So Cilium can own networking and install `CiliumNetworkPolicy`.

**kubeconfig_path** in `cluster.tf` writes `terraform/devsecops-lab-config` (**IMPROVEMENT APPLIED** vs relying only on `~/.kube/config`).

**NOT CURRENTLY IMPLEMENTED:** cloud cluster, multi-master, etcd backup, PVCs, Ingress controller.

**Oral:** “My cluster is a disposable Kind lab on my laptop, declared in Terraform, with Cilium instead of Kindnet so I can isolate a pod with a CiliumNetworkPolicy.”

---

# 7. Docker and Containerization

### Level 1
Docker packages processes. Kind uses that to fake Kubernetes nodes. Nginx is a Docker image.

### Level 2
Image = layers; container = isolated process. Kind nodes are privileged containers running kubelet.

### Level 3
`demo.tf`: `image = "nginx:latest"`. No `Dockerfile`, no Compose, collector not containerized.

### Level 4
“I did not dockerize the AI. Docker is how Kind and nginx run.”

| Parameter | Value | Purpose | Effect |
|-----------|-------|---------|--------|
| nginx tag | `latest` | demo web server | not pinned; pull may change |

**OPTIONAL PRODUCTION IMPROVEMENT:** pin digest; build collector image; run collector as Deployment + Service (ClusterIP), webhook in-cluster.

---

# 8. Kubernetes

### Concepts actually used

| Concept | Used? | Evidence |
|---------|-------|----------|
| Pod / Deployment | Yes | `demo.tf` |
| Namespace | Yes | demo-app, falco, monitoring |
| Label | Yes | `app=nginx-demo`, `quarantine=true` |
| Annotation | Yes | `devsecops.ai/*` |
| Service | Grafana/Prometheus NodePort via Helm; **no** Service for nginx in `demo.tf` |
| ConfigMap / Secret | Falco rules via Helm values; **no** app Secret for Jira |
| RBAC | Chart defaults only; **no custom Role** in repo |
| NetworkPolicy | **CiliumNetworkPolicy**, not `networking.k8s.io` |

### How Falco relates to Kubernetes

Falco (DaemonSet from chart) sees syscalls on the node and enriches with `k8s.pod.name`, `k8s.ns.name` when the process is in a pod. That is **not** the Kubernetes API “calling Falco”; it is Falco reading kernel + metadata.

Remediation **does** call the Kubernetes API: Python `subprocess` `kubectl`.

**Jury:** “Kubernetes does not run the model. Kubernetes is the *place* we observe and the *API* we use to isolate.”

---

# 9. Infrastructure as Code / Terraform

### What / why
Declare Kind + Helm so the lab is repeatable.

### Parameters verified

| Parameter | Value | File | Effect |
|-----------|-------|------|--------|
| cluster name | `devsecops-lab` | cluster.tf | Kind cluster id |
| disable_default_cni | true | cluster.tf | Cilium required |
| pod_subnet | 10.244.0.0/16 | cluster.tf | pod IPs |
| Cilium chart | 1.16.0 | cilium.tf | CNI version |
| Falco driver | modern_ebpf | falco.tf | no kernel module build |
| Falcosidekick UI | false | falco.tf | no Redis/UI |
| webhook | host:5002/events | falco.tf + variables.tf | path to Flask |
| collector_host default | 172.17.0.1 | variables.tf | docker0 on many Linux hosts |
| Grafana | admin/admin, NodePort 30030 | monitoring.tf | lab login |
| Prom scrape | **192.168.41.128:8000** | monitoring.tf | **not** using var.collector_host |
| Alertmanager | enabled true | monitoring.tf | no custom routes in repo |

**Providers:** kind `tehcyx/kind` ~> 0.5, kubernetes ~> 2.27, helm ~> 2.13 — `versions.tf`. Local `.terraform` may resolve helm 2.17 / kubernetes 2.38 — lockfile exists.

**If Terraform fails:** Docker down, Helm timeout 600s on Falco, Cilium not ready.

**OPTIONAL PRODUCTION IMPROVEMENT:** remote state, scrape via variable, Grafana password from Secret.

---

# 10. Runtime Security / eBPF / Falco

### Level 1 — eBPF
A way to run small programs in the Linux kernel safely. Falco uses this to watch syscalls without writing a custom kernel module.

### Level 2
`driver.kind = modern_ebpf` in `falco.tf`. This project contains **no** `.bpf.c` source.

### Level 1 — Falco
A rules engine: if condition then alert.

### Custom rules (deployed file)

**File:** `terraform/falco_rules.local.yaml`  
**Loaded by:** `falco.tf` `customRules["falco_rules.local.yaml"] = file(...)`

| Rule | Condition (simplified) | Priority |
|------|------------------------|----------|
| Suspicious outbound connection | outbound + container + rport ∉ {80,443,53} | WARNING |
| Unexpected inbound… | accept + lport ∉ {80,443,53} | WARNING |
| Sensitive file access outside shadow | open_read `/etc/ssh` or `/root/.ssh` or `*.pem` | CRITICAL |
| Sensitive environment variable… | `/proc/self/environ` or `/proc/*/environ` | WARNING |
| Unexpected package manager | apt, yum, dnf, apk, pip, pip3 | WARNING |
| Unexpected process spawned… | bash, sh, zsh, nc, ncat, curl, wget | WARNING |
| Baseline normal activity demo-app | spawned_process + `k8s.ns.name = demo-app` | INFORMATIONAL |

Outputs include `%evt.duration` and `%proc.duration` so Falcosidekick can fill `output_fields` for the collector.

**Chart default rules** also appear in live CSV (`Contact K8S API Server From Container`, `Drop and execute new binary in container`, `Terminal shell in container`, `Read sensitive file untrusted`, …).

**Mismatch to remember:** IA IOC list includes `/etc/passwd`; custom Falco sensitive-file rule does **not**. `/etc/passwd` may still hit **default** Falco `Read sensitive file untrusted` on the live cluster.

**Inbound rule:** CURRENTLY IMPLEMENTED as YAML; **NOT** used in `demo_attaque.sh`.

---

# 11. Security Detection Pipeline

Three distinct boxes:

1. **Falco detection** — boolean rule match on syscalls.  
2. **ML analysis** — numeric score 0–100 + status string.  
3. **Response automation** — kubectl if score ≥ 70.

Falco can fire and ML still say NORMAL (e.g. baseline + benign recon arbitration). ML can score high because of IOC in cmdline even if one Falco rule is “only” WARNING.

---

# 12. Data Collection

### Live

- **Source:** Falcosidekick JSON → collector append.  
- **File:** `datasets/falco_events_dataset_v2.csv`  
- **Count in repo at inspection:** **2810** data rows (+ header).  
- **One row:** one Falco alert after mapping to 22 columns.

### Synthetic

- **Source:** `generate_smart_testdata.py` then `generate_personas.py` (which calls `g.main()` again and appends uid 472 + extra admin rows).  
- **File:** `datasets/falco_events_enriched.csv`  
- **Count:** **1155** rows.  
- Users in synth (count): admin 372, dev 248, root 215, python 200, bot 120.

### Representative raw synth row

`timestamp=2026-08-14T00:03:13.000000Z`, `priority=Informational`, `rule=Baseline normal activity demo-app`, `user=dev`, `user_uid=1001`, `command=id`, `command_duration_ms=9.02`.

### Representative live row

`rule=Terminal shell in container`, `priority=Notice`, `command=sh -c nginx -s reload`, `user=root`, `user_uid=0`.

### Schema (`settings.py` `FALCO_CSV_COLUMNS`)

timestamp, uuid, **priority**, rule, event_scope, node, namespace, pod, container_id, container_name, image, image_tag, user, user_uid, proc_name, proc_exepath, parent_process, command, event_type, file, connection, command_duration_ms.

**priority** is stored; it is **not** an RF feature (no `priority_enc` anywhere in `src/`).

---

# 13. Data Preprocessing

Pipeline in `run_train.py` + `GlobalModel.extract_features` + `encode`:

| Step | Input | Operation | File | ML impact |
|------|-------|-----------|------|-----------|
| Repair CSV | live file 21/22 cols | map to canonical 22 | `csv_io.py` | train can load mixed history |
| Concat | live + synth | `pd.concat` | `run_train.py` | mixed distribution |
| Filter | rows | drop empty/`unknown` pod | `run_train.py` | drop node-scope |
| UID clean | user_uid | strip `.0`, drop nan | `run_train.py` | UBA keys |
| Temporal | timestamp | Tunis hour, weekend, off-hours, tz flag | `time_features.py` | RF + UBA |
| Command syntax | command | verb, length, args, pipe, redirect, `$(` | `features.py` / `global_model.py` | RF |
| Duration | duration fields | parse ns/ms/s, cap 120s | `parse_duration_ms` | RF + UBA |
| Burst | timestamps per pod | count last 5 min | `global_model.py` train loop | RF |
| Label | rule + command domain | `label_is_anomaly` | `global_model.py` | RF *y* |
| Encode | command_verb, event_scope | LabelEncoder **on full df** | `encode()` | leakage (see §15) |
| Split | X, y | first 75% / last 25%, **no shuffle** | `train()` | dubious test set |
| UBA scale | 8 numeric cols per uid | StandardScaler + IF | `uba_model.py` | IF only |
| Missing X | NaN | fillna(0) | `encode` | |

**Duplicates:** not dropped. **Class imbalance:** `class_weight="balanced"` on RF.  
**NOT CURRENTLY IMPLEMENTED:** sklearn Pipeline, StratifiedKFold, SMOTE.

Default if timestamp unparsable: `hour_of_day=12`, `is_off_hours=0`.

---

# 14. Feature Engineering

**RF vector is exactly `FEATURE_COLS` in `src/core/features.py`.**

`id_night` — **does not exist** (use `is_off_hours`).  
`priority_enc` — **does not exist**.

| Feature | Source | Meaning | Type | Transformation | Why useful | Training? | Inference? |
|---------|--------|---------|------|----------------|------------|-----------|------------|
| hour_of_day | Falco `time` | Hour in Africa/Tunis | int 0–23 | tz convert | night vs office | yes | yes |
| day_of_week | timestamp | Mon=0 … Sun=6 | int | pandas | weekly pattern | yes | yes |
| is_weekend | day_of_week | Sat/Sun | bin | 5,6 | weekend admin | yes | yes |
| is_off_hours | hour | &lt;8 or ≥18 | bin | env BUSINESS_HOUR_* | after hours | yes | yes |
| timestamp_has_tz | raw string | has Z or ±offset | bin | regex | data quality | yes | yes |
| command_length | cmdline | char count | int | len | long payloads | yes | yes |
| command_arg_count | cmdline | token count | int | split | complexity | yes | yes |
| command_duration_ms | Falco durations | runtime ms | float | parse + cap 120000 | apt vs ls | yes | yes |
| is_long_runtime | duration | ≥3000 ms | bin | threshold | long jobs | yes | yes |
| has_pipe | cmdline | `\|` | bin | contains | chaining | yes | yes |
| has_redirect | cmdline | `>` `>>` | bin | | writes | yes | yes |
| has_dollar_subshell | cmdline | `$(` | bin | | indirection | yes | yes |
| is_shell_spawned | proc/parent | sh/bash/zsh or parent runc/sh/bash | bin | | shell in nginx | yes | yes |
| has_indirection | sh + verb in NETWORK or cat/ls | bin | | `sh -c curl` | yes | yes |
| event_count_5min | same pod timestamps | events in [t-5m, t] | int | window | burst | yes | **history at collector boot** |
| command_verb_enc | first token after stripping `sh -c` | encoded verb | int | LabelEncoder | action type | **fit on full df** | unknown verb → 0 |

**Computed but not in FEATURE_COLS** (so **not** RF inputs unless an old pickle listed extra columns):

- `has_suspicious_keyword` (ignores bind/connect/shell/reverse)
- `has_suspicious_extension`
- `is_sensitive_file` — used by **UBA + engine**
- `target_domain` — used by **UBA + engine**; `predict()` may encode `target_domain_enc` but FEATURE_COLS has no such name
- `event_scope_enc` — encoder trained, not in FEATURE_COLS

**Leakage note:** `rule` is **not** in X (good). Label **is** a function of `rule` (target leakage via proxy features of the same command).

---

# 15. Data Leakage Analysis

| Issue | What could leak | Why leakage | Impact | Status | Correction in repo |
|-------|-----------------|-------------|--------|--------|-------------------|
| Falco-derived label | y from rule name | RF predicts “would Falco fire this class of rule” | Optimistic AUC vs real attacks | **Confirmed conceptual** | Mitigated: `max_depth=4`; rule string not in X. **Not fully corrected** |
| LabelEncoder before split | verb IDs see test verbs | encoder fit on all rows then 75/25 split | Test not independent | **Confirmed issue** | **Not corrected** |
| Split not shuffled / not time-based | concat live then synth, cut 75% | test may not be “future” | Misleading metrics | **Potential / confirmed weak protocol** | **Not corrected** |
| Burst uses t-5min ≤ t | future events | would need times > t | — | **No issue** for that window | — |
| Live burst stale history | undercount burst | not leakage, **product bug** | demo burst features weak | IMPLEMENTED BUT LIMITED | OPTIONAL: update df_history each event |
| IF fit on all uid rows including attacks | IF sees outliers it should detect | contamination 0.15 assumes 15% outliers in train mix | IF not a clean baseline model | **Potential issue** | OPTIONAL: train IF on normal-only |
| uuid/pod in X | identity | — | — | **No issue** (not in FEATURE_COLS) | — |
| priority in X | Falco severity ≈ label | — | — | **No issue** (not in X) | — |

**Oral honesty:** “I reduced leakage of the *rule name* into features. I did **not** eliminate leakage of Falco’s *decision* into the label. I would fit encoders on train only and split by time.”

---

# 16. Machine Learning Architecture

**Hybrid, two layers + rules:**

```text
event_dict
    ├─ GlobalModel.predict → P(anomaly) ∈ [0,1] → ×100 = global_score
    ├─ UBAModel.score → 0–100 + reasons
    └─ engine arbitration (min/max caps) → combined_score, status
```

**Problem type:**

- Layer 1: **binary classification** (Normal vs Anomaly) with a **weak Falco-based label**.
- Layer 2: **heuristic UBA** + **unsupervised** Isolation Forest per UID.
- Output used in production path: **combined_score**, not RF class `predict()`.

Weights: **35% RF + 65% UBA** then additional if-rules (`engine.py`). Those ifs are **not elif**: several can apply; `combined` is updated sequentially; the `arbitrage` **string** is overwritten by the **last matching if**.

---

# 17. Random Forest

### Level 1
Many small decision trees vote whether the event looks like the “anomaly” class.

### Level 2
sklearn `RandomForestClassifier`. Default **bootstrap=True**, **max_features='sqrt'** (not overridden). Each tree: bootstrap sample, random feature subset at splits, Gini (sklearn default). Output used: `predict_proba[:, 1]`.

### Level 3 — hyperparameters in code

```
n_estimators=80, max_depth=4, min_samples_split=25,
min_samples_leaf=12, class_weight="balanced", random_state=42, n_jobs=-1
```

Comment in `global_model.py`: shallow trees to avoid a “perfect” AUC that **copies Falco**.

**Block-by-block `train()`:** extract_features → encode → length/class checks → split 75/25 → fit → print classification_report, ROC-AUC, confusion_matrix, importances → pickle three files.

**`predict()`:** build one row matching `feature_cols` from pickle; unknown encoded categories → 0.

**Why RF:** tabular mixed features, importances for the jury, CPU-friendly.  
**Why not deep learning:** no such code; small tabular set.

**Cyber:** FN = miss (bad); FP = extra isolate (also bad). Shallow RF + UBA caps try to cut FP on benign recon.

---

# 18. Isolation Forest

### Level 1
Points that are easy to isolate with random cuts are treated as anomalies.

### Level 2
sklearn IsolationForest: isolation trees, anomaly linked to **short path length**. `contamination=0.15` sets the internal proportion expected anomalous; `predict()` returns **-1** (outlier) or **1** (inlier). This repo **does not** read `decision_function` / `score_samples`.

### Level 3
Trained per UID if **≥ 10** events. Features: hour, day_of_week, command_length, is_sensitive_file, has_pipe, has_redirect, is_off_hours, command_duration_ms. Scaled with StandardScaler (fit on that uid’s matrix). Saved `models/uba_if_<uid>.pkl`.

On score: if -1, **+30** UBA points.

**Difference vs RF:** no Falco label for IF; it asks “is this unusual **for this UID**?”  
**FP:** unusual but legitimate admin action.  
**Pickles present:** 0, 1000, 1001, 472, 999. Profiles also `uba_2000.json`, `uba_65534.json` **without** matching IF files (UID 65534 = nobody on Linux — live residue).

---

# 19. Model Training

```text
CSV live + synth
 → filter pods / uid
 → extract_features + label
 → LabelEncoder full data
 → RF fit on first 75%
 → evaluate last 25% (print only)
 → pickle RF
 → for each uid: JSON profile; IF if n≥10
```

**Files:** `run_train.py` → `HybridEngine.train` → `GlobalModel.train` + `UBAModel.train_all_profiles`.

**Load at inference:** `engine.load()` at collector import time.

---

# 20. Model Evaluation

**Calculated in code** (`sklearn.metrics`):

| Metric | How | Result in git |
|--------|-----|----------------|
| Precision, recall, F1, support | `classification_report` | **Not stored** — console only |
| Accuracy | included in that report | **Not stored** |
| Confusion matrix | `confusion_matrix` | **Not stored** |
| ROC-AUC | `roc_auc_score` if y_test has 2 classes | **Not stored** |
| Feature importance | `feature_importances_` | **Not stored** |
| Combined score 0–100 | live | logs / Prometheus gauge |

**Do not invent numbers.** Re-run:

```bash
cd src && python run_train.py
```

**Cyber reading:** treat printed Anomalie-class **recall** as “how often we recover Falco-like positives,” not “true attacker catch rate.”

**NOT CURRENTLY IMPLEMENTED:** MLflow, saved metrics JSON, PR curves.

`demo_decision_table.py` is a **manual** sanity table (8 cases), not assertions.

---

# 21. Real-Time Inference

```text
New Falco JSON
 → parse fields (collector.py)
 → ignore if no pod
 → RF: features + encoder.transform
 → UBA: histogram, verbs, domains, sensitive_rate, burst, duration, IF
 → mix 0.35/0.65
 → sequential min/max rules
 → status from thresholds 20 / 45 / 70
 → Prometheus
 → if ≥ 70: remediation + optional Jira/mail
 → append CSV
 → JSON {status, score}
```

**Concrete demo command** (cmdline contains environ path + `evil.com`):

`sh -c 'cat /proc/self/environ; apt-get --version; curl -s --max-time 3 http://evil.com:8080/ || true'`

- Falco: spawn sh/curl, baseline, environ, apt-get, outbound 8080 if curl exists.  
- `target_domain` → `external_malicious` (`iocs.json`).  
- `is_sensitive_target` true (`/proc/self/environ`).  
- Engine rule 5 can **raise combined to ≥ 85** if malicious **and** (sensitive or off-hours or burst≥10).  
- Containment **only if final combined ≥ 70**.

Unknown UID: UBA returns **50** + “Utilisateur inconnu”. RF still runs. Unknown verb encoding → 0.

---

# 22. Falco + AI Integration

| Question | Answer from repo |
|----------|------------------|
| Falco detects what? | Syscall patterns in rules (custom + defaults) |
| Data produced? | JSON: time, rule, priority, output_fields |
| How AI receives it? | HTTP POST Falcosidekick → Flask |
| Preprocessing? | Field map + same feature functions as train |
| Model output? | combined_score, status, uba_reasons, arbitrage |
| Decision? | thresholds in engine + collector |
| After decision? | metrics, CSV; maybe kubectl |
| Does AI trigger containment? | **Yes, if score ≥ 70**: Python runs kubectl. Cilium enforces CNP already applied |
| Automatic or manual? | Automatic label; **unquarantine is manual** |
| Evidence? | Pod kept Running; annotations; CSV; optional ticket |

**Do not say:** “the neural net calls the Kubernetes scheduler.”  
**Do say:** “If the hybrid score is at least 70, my collector labels the pod; Cilium drops traffic because of a policy that matches that label.”

---

# 23. Monitoring / Prometheus / Grafana

**Prometheus (concept):** pull metrics over HTTP.  
**Here:** collector `start_http_server(8000)` exposes:

- `devsecops_falco_events_total`
- `devsecops_ai_anomaly_score{user,pod,rule}` Gauge
- `devsecops_ai_alerts_total{severity}`
- `devsecops_remediations_total{status}`
- `devsecops_jira_tickets_total{status}`

**Grafana:** visualize PromQL. File `config/grafana_dashboard.json` — thresholds 45 and 70 on the score graph.

**Alerting in Grafana/Alertmanager:** no custom alerting rules in repo. Business alert = Jira/email.

**Test:** open Grafana; if targets down, scrape IP is wrong.

**OPTIONAL PRODUCTION IMPROVEMENT:** use `var.collector_host`; ServiceMonitor; disable lab `admin/admin`.

---

# 24. Incident Response / Containment

**CURRENTLY IMPLEMENTED**

1. Check already `quarantine=true` → skip Jira/mail.  
2. Annotate timestamp, score, rule.  
3. Label `quarantine=true`.  
4. Count quarantined pods with same `app=` label; `kubectl scale --replicas=quarantined+1`.  
5. CNP: ingressDeny/egressDeny entities `all` for labeled endpoints.

**Forensics:** process not killed (explicit).  
**NOT CURRENTLY IMPLEMENTED:** memory dump, image snapshot, secret rotation, auto-unlabel, SIEM.

**If kubectl fails:** remediation status `failed`; still CSV + metrics.

**Production after quarantine (oral, not code):** human IR, rebuild pod, rotate secrets, then remove label.

---

# 25. Configuration Reference

| File | Purpose | Important parameters | Dependencies | Impact |
|------|---------|----------------------|--------------|--------|
| terraform/cluster.tf | Kind cluster | 2 nodes, no default CNI, kubeconfig_path | Docker | whole lab |
| terraform/cilium.tf | CNI | 1.16.0, API host/port | Kind | network + CNP |
| terraform/falco.tf | Falco | eBPF, webhook, no UI | Cilium | detection |
| terraform/falco_rules.local.yaml | custom rules | 7 rules + durations | Helm values | which events |
| terraform/demo.tf | nginx | latest, replicas 1 | ns demo-app | target |
| terraform/quarantine-policy.tf | CNP | selector quarantine=true | Cilium | isolation |
| terraform/monitoring.tf | Prom/Graf | **192.168.41.128:8000**, admin/admin | Kind | dashboards |
| terraform/variables.tf | host ports | 172.17.0.1, 5002, 8000 | docker0 | webhook |
| src/config/settings.py | paths, Jira env, CSV schema | KUBECONFIG, DATASET | — | IO |
| src/config/iocs.json | IOC lists | domains, paths, verbs, uids | iocs_loader | UBA/engine |
| .env.example | documentation | TZ, Jira, Gmail | **not auto-loaded** | you must `export` |
| src/requirements.txt | pip | flask, sklearn, … | Python | runtime |
| config/grafana_dashboard.json | UI | PromQL | Grafana | defense visuals |
| scripts/demo_attaque.sh | one scenario | kubectl exec | cluster+collector | demo |

**NOT CURRENTLY IMPLEMENTED:** Dockerfile, Compose, standalone K8s YAML, CI YAML.

**iocs.json malicious_domains:** evil.com, attacker.com, malware.com, pastebin.com, c2-server.com, darkweb.link, exfil.io.

---

# 26. Testing and Validation

| Test | Objective | Command/Method | Expected | Actual result | Evidence |
|------|-----------|----------------|----------|---------------|----------|
| Cluster up | nodes Ready | `kubectl get nodes` | 2 Ready | **Not verified in git** | local only |
| Pods | Falco/Cilium/nginx | `kubectl get pods -A` | Running | **Not verified in git** | |
| Falco rule fire | custom rules | demo script + falco logs | rule names in logs | **Not verified in git** | run live |
| Collector | JSON accepted | Flask log / HTTP 200 | Event line + score | **Not verified in git** | |
| RF metrics | sklearn quality | `python run_train.py` | printed report | **Not in git** | console |
| Decision table | arbitration | `python demo_decision_table.py` | 8 printed rows | **Not in git** | console |
| Quarantine | label | `kubectl get pods -n demo-app --show-labels` | quarantine=true if score≥70 | depends on score | |
| Grafana | metrics | UI | counters increase | depends on scrape IP | |
| Jira/mail | notify | env + critical event | ticket/mail | skipped if no env | code paths |
| pytest | unit tests | — | — | **NOT CURRENTLY IMPLEMENTED** | no tests/ |

Do not invent “we achieved 99% accuracy.”

---

# 27. Security Demonstration Scenario

### Normal state
nginx-demo Running, no `quarantine` label, collector listening, Falcosidekick webhook reachable.

### Suspicious action (safe)
Read container environ, `apt-get --version` (no install), optional curl to lab IOC **port 8080**, 3s timeout.

### Falco
See comments in `scripts/demo_attaque.sh` (rules listed there).

### Log
Falco pod logs + collector `[+] Event`.

### AI
Parse → features (sensitive + evil.com) → RF + UBA → possibly floor 85 → status.

### Decision
≥70 critical else lower bands.

### Alert
Prometheus counters; Jira/Gmail if env set.

### Response
label + scale if critical.

### Verification
`--show-labels`, `kubectl get deploy nginx-demo -n demo-app`, Grafana.

### Manual commands

```bash
export KUBECONFIG=/path/to/terraform/devsecops-lab-config
POD=$(kubectl get pods -n demo-app -l app=nginx-demo -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n demo-app "$POD" -- sh -c 'cat /proc/self/environ; apt-get --version; curl -s --max-time 3 http://evil.com:8080/ || true'
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=40
kubectl get pods -n demo-app --show-labels
```

### Script, step by step (`scripts/demo_attaque.sh`)

1. `set -euo pipefail` — fail fast.  
2. Find pod by label.  
3. Exit if missing.  
4. `kubectl exec` the one-liner.  
5. Print labels (quarantine may appear **seconds later** while Falco/IA run).  
6. User checks Flask terminal.

Cleanup:

```bash
kubectl label pod -n demo-app -l app=nginx-demo quarantine-
kubectl scale deploy nginx-demo -n demo-app --replicas=1
```

---

# 28. Troubleshooting

### Webhook empty, no Flask events
**Cause:** Falcosidekick cannot reach 172.17.0.1:5002 (wrong IP, collector down, firewall).  
**Investigation:** Falcosidekick logs; `curl` from a debug pod.  
**Solution:** `terraform apply -var='collector_host=YOUR_IP'`; start `python collector.py`.  
**Lesson:** collector is **outside** the cluster.

### Grafana empty
**Cause:** scrape `192.168.41.128:8000` ≠ this machine.  
**Solution (OPTIONAL PRODUCTION IMPROVEMENT):** wire `var.collector_host`.

### Score &lt; 70 in daytime
**Cause:** caps at 55 without strong IOC/burst (`engine.py`).  
**Lesson:** demo includes `evil.com` + environ to hit floor rules.

### nginx has no curl
**Cause:** image contents.  
**Mitigation:** `|| true`; apt-get and environ still fire Falco.

### CSV pandas errors
**Cause:** 21 vs 22 columns.  
**Solution:** `repair_falco_csv` in `run_train.py`.

Do not invent undocumented outages.

---

# 29. Current Implementation vs Production Improvements

### CURRENTLY IMPLEMENTED
Kind lab, Cilium CNP, Falco eBPF + webhook, hybrid ML, kubectl quarantine, optional Jira/Gmail, Prometheus metrics, Grafana JSON, one safe demo script.

### IMPROVEMENT APPLIED
Single `demo_attaque.sh` instead of S0–S8; kubeconfig_path; removed duplicate unused Falco YAML under `src/`.

### OPTIONAL PRODUCTION IMPROVEMENT
Collector as in-cluster Service + TLS + auth; RBAC Role limited to label/scale; pin images; Terraform scrape variable; encoder fit on train only; time-based split; human labels; IF on clean baseline; update history online; model drift monitoring; CI (`terraform validate`, tests); image scanning; HA; centralized logging/SIEM; secret manager; disable Grafana default password; retraining pipeline; inbound demo only with a dedicated Service; post-quarantine IR playbook in code.

---

# 30. Technical Knowledge and Skills Acquired

Fill **Before** with your real starting level. The rest is repo-true.

### Kubernetes / Kind
**Implementation:** Kind via Terraform, Deployment, labels, namespaces.  
**Learning:** CNI, why Cilium, label-driven policy.  
**Now:** explain Pod vs Deployment; show quarantine label.

### Terraform
**Implementation:** Kind/Helm/K8s resources.  
**Learning:** providers, values injection for Falco rules.  
**Now:** map each `.tf` file to a runtime piece.

### Falco / eBPF
**Implementation:** custom YAML, Helm driver setting.  
**Learning:** rules vs syscalls; default rules still fire.  
**Now:** walk a rule condition to a JSON field.

### Python / Flask
**Implementation:** webhook glue.  
**Learning:** out-of-cluster integration.  
**Now:** trace one POST through `collector.py`.

### Random Forest / Isolation Forest
**Implementation:** sklearn, pickles, hybrid engine.  
**Learning:** classification vs anomaly; leakage.  
**Now:** list FEATURE_COLS from memory using this report.

### Prometheus / Grafana
**Implementation:** client metrics + JSON dashboard.  
**Learning:** pull model; labels on metrics.  
**Now:** name the five metric families.

### Cyber / DevSecOps
**Implementation:** detect → score → contain → ticket.  
**Learning:** isolate ≠ delete; forensics.  
**Now:** production IR after quarantine (human).

**NOT relevant as implemented:** Maven, GitHub Actions, Istio, Vault.

---

# 31. What I Personally Implemented

Attribute only what the repo shows (adjust if you had a teammate):

| Area | Evidence |
|------|----------|
| Infrastructure | `terraform/*.tf` |
| Runtime rules | `falco_rules.local.yaml` |
| Collector / metrics | `collector.py` |
| Features / time / IOC | `features.py`, `time_features.py`, `iocs.json` |
| RF / UBA / engine | `global_model.py`, `uba_model.py`, `engine.py` |
| Training | `run_train.py`, generators |
| Containment | `remediation.py`, CNP |
| Ticketing / mail | `jira_ticketing.py`, `alerting.py` |
| Demo / docs | `demo_attaque.sh`, guides, this report |
| Debugging | csv_io 21/22 cols; ignore node events; already_isolated short-circuit |

Do not claim CI, Docker image, or inbound exploit labs.

---

# 32. How I Would Explain the Project to the Jury

“I built a laptop Kubernetes lab with Terraform and Kind. The application is a normal nginx pod. Falco, using eBPF, watches syscalls. Custom rules catch shells, package managers, environ reads, and odd ports. Falcosidekick sends each alert to a Flask service on my machine. That service does not blindly quarantine. A Random Forest gives a global ‘does this look like the Falco-anomaly class’ probability. An UBA profile per Linux UID asks if this user usually does this at this hour in Tunisia. Isolation Forest adds a plus-thirty if the point is an outlier for that user. I mix 35/65 then apply explicit caps so a developer `ls` does not isolate the pod, while environ plus a lab C2 domain can pass 70. Above 70 I only **label** the pod. Cilium already has a policy: labeled pods lose all network. I scale the Deployment so users still get a healthy replica. The bad pod stays up for evidence. Jira and Gmail are optional. This is a prototype, not production: the collector is on the host, Prometheus may scrape an old IP, and my RF labels come from Falco itself.”

---

# 33. Possible Jury Questions and Answers

**Why Falco?** Need runtime syscalls on K8s, not only app logs. Evidence: Helm Falco + rules YAML.

**Why not only Falco?** Too many events; no user baseline. Engine + UBA.

**What is eBPF?** Safe kernel probes. We use Falco’s driver, we didn’t write BPF C.

**Event to model?** Sidekick POST → collector parse → `HybridEngine.predict`.

**Features?** Table in §14. No `id_night`, no `priority_enc`.

**Why RF?** Tabular, importances, sklearn; shallow to avoid cloning Falco.

**Why IF?** Per-user unsupervised complement.

**Classification vs anomaly?** RF has labels; IF does not use those labels.

**Leakage?** Label from Falco; encoder fit all data. Mitigated not eliminated.

**New event?** §21. Unknown user → UBA 50.

**Does AI isolate the pod?** If score ≥ 70, Python kubectl label; Cilium enforces.

**Evidence?** No delete; annotations; CSV.

**K8s ↔ Falco?** Falco on nodes + metadata; kubectl from collector for response.

**Terraform?** Repeatable lab.

**Prometheus / Grafana?** Show scores; they do **not** decide quarantine.

**Component fails?** Collector down → no score/containment, Falco still logs. kubectl fail → failed remediation counter. Wrong scrape → blind Grafana.

**What did you implement?** §31.

**Production changes?** §29 OPTIONAL list.

**False positive?** Caps for recon; still possible; unlabel manually.

**Why 70?** Hardcoded in collector/engine; not cross-validated in repo.

**Why 35/65?** Hardcoded in `engine.py`; not a searched hyperparameter (say that honestly).

**pastebin.com malicious?** It is in `iocs.json`; discuss as a lab IOC, debatable in real SOC.

---

# 34. Limitations

- Lab Kind, not production cluster.  
- Collector off-cluster, unauthenticated webhook.  
- RF labels ≠ human IR labels.  
- Metrics of RF not saved.  
- History burst stale.  
- Scrape IP hardcoded.  
- nginx `latest`; maybe no curl.  
- No unit tests, no CI.  
- Inbound rule unused in demo.  
- IF trained on mixed data.  
- Encoder leakage.  
- Grafana admin/admin.  
- Quarantine is all-or-nothing (breaks DNS too).

---

# 35. Future Work

All **OPTIONAL PRODUCTION IMPROVEMENT**: in-cluster collector, proper ML protocol, saved metrics, tests, CI, pin images, scrape variable, IF on baseline, online history, SIEM, secret rotation playbooks, human-in-the-loop unquarantine.

---

# 36. Final Technical Summary

The repository implements a **Kind + Cilium + Falco (eBPF) + host Flask hybrid RF/UBA + kubectl quarantine + optional Jira/Gmail + Prometheus metrics** pipeline. AI **does** trigger containment **only above score 70** via `kubectl`, not by “controlling Kubernetes” as a controller. Docker is Kind/nginx, not a custom app image. There is **no** CI/CD, Maven, or Falcosidekick UI.

Study path: this file → `Guide_Utilisation.md` (commands) → `src/models/engine.py` + `features.py` + `collector.py` + `terraform/falco_rules.local.yaml` + `scripts/demo_attaque.sh`.

Re-run `python src/run_train.py` before the defense if the jury asks for **numbers**; they are not in Git.
