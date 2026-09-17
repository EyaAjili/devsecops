output "kubeconfig_path" {
  description = "Fichier kubeconfig créé par Kind"
  value       = "${path.module}/devsecops-lab-config"
}

output "grafana_nodeport" {
  description = "Grafana (utilisateur admin / mot de passe admin)"
  value       = "http://localhost:30030 (NodePort) ou kubectl -n monitoring port-forward svc/kube-prometheus-stack-grafana 3000:80"
}

output "prometheus_nodeport" {
  description = "Prometheus UI"
  value       = "http://localhost:30090"
}

output "falco_webhook" {
  description = "URL configurée dans Falcosidekick"
  value       = "http://${var.collector_host}:${var.collector_webhook_port}/events"
}

output "prometheus_scrape_target" {
  description = "Cible scrape du collector IA"
  value       = "${var.collector_host}:${var.collector_metrics_port}"
}
