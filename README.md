# Prototype DevSecOps IA (PFE)

Détection d’anomalies sur un lab **Kind** : Falco → Falcosidekick → collector Flask (Random Forest + UBA) → quarantaine Cilium. Si le score ≥ 70 : ticket Jira et email (optionnels).

```
Kind + Cilium + Falco
        │
        ▼
collector.py (:5002 webhook, :8000 métriques)
        │
        ├─ models/engine.py  (RF 35 % + UBA 65 %)
        └─ score ≥ 70 → label quarantine=true → CiliumNetworkPolicy
```

## Ce qui existe

- Cluster Kind, CNI Cilium, Falco (eBPF) + webhook Falcosidekick
- Règles custom : `terraform/falco_rules.local.yaml` (fichier réellement déployé)
- IA hybride, remédiation Cilium, métriques Prometheus, dashboard Grafana
- Jira et Gmail **si** les variables d’environnement sont définies

## NOT CURRENTLY IMPLEMENTED

- Image Docker custom / Dockerfile / docker-compose (Kind utilise Docker ; l’app démo est `nginx:latest`)
- Pipeline CI/CD
- UI Falcosidekick (désactivée dans `falco.tf`)
- Attaque réseau entrante (règle Falco présente, **pas** rejouée en démo)

`terraform/demo.tf` et `terraform/monitoring.tf` sont en lecture seule (propriétaire `nobody`). Ils n’ont pas pu être réécrits ici. Prometheus scrape encore l’IP `192.168.41.128:8000` ; Alertmanager est encore activé dans ce fichier. Les alertes métier du PFE restent Jira + email.

## Démarrage rapide

Voir **Guide_Utilisation.md**. Démo unique : `scripts/demo_attaque.sh`.
