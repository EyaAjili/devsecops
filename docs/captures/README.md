# Captures à insérer dans le rapport

Aucun fichier image n’était présent dans le dépôt au moment de la rédaction.
Enregistrer les PNG ci-dessous dans **ce dossier**, sous les noms indiqués, puis les coller dans `Rapport_PFE.md` aux figures correspondantes.

| Fichier | Commande / écran | Figure |
|---------|------------------|--------|
| `01-architecture-live.png` | Dessin ou export du schéma (Kind → Falco → Flask → Cilium) | 1 |
| `02-kubectl-get-pods.png` | `kubectl get pods -A` | 2 |
| `03-falco-logs.png` | `kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=40` après la démo | 3 |
| `04-collector-logs.png` | Terminal `python collector.py` : ligne Event + score | 4 |
| `05-demo-attaque.png` | Sortie de `./scripts/demo_attaque.sh` | 5 |
| `06-quarantine-labels.png` | `kubectl get pods -n demo-app --show-labels` | 6 |
| `07-cilium-policy.png` | `kubectl -n demo-app get ciliumnetworkpolicy quarantine-policy -o yaml` (extrait) | 7 |
| `08-grafana-dashboard.png` | Grafana : dashboard « DevSecOps AI Prototype » | 8 |
| `09-decision-table.png` | `python demo_decision_table.py` | 9 |
| `10-jira-ticket.png` | Ticket Jira Cloud **si** les variables sont configurées | 10 |
| `11-gmail-alerte.png` | Email d’alerte **si** Gmail est configuré | 11 |
| `12-run-train.png` | Sortie `python run_train.py` (rapport RF, ROC-AUC, confusion) | 12 |

**Optionnel (limites du prototype) :** Grafana vide si Prometheus scrape encore `192.168.41.128:8000` alors que la machine a une autre IP — capturer aussi Prometheus → Status → Targets.
