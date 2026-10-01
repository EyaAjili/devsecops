# Adresse du collector Flask vu depuis le cluster Kind (conteneurs Docker).
# Sur Linux, 172.17.0.1 est en général l'IP du pont docker0 (l'hôte).
# Si le webhook Falco n'arrive pas, remplacer par l'IP de la machine (ip -4 addr).
variable "collector_host" {
  type        = string
  description = "IP de la machine hôte, joignable depuis les pods Kind"
  default     = "172.17.0.1"
}

variable "collector_webhook_port" {
  type    = number
  default = 5002
}

variable "collector_metrics_port" {
  type    = number
  default = 8000
}

variable "falco_webhook_token" {
  type        = string
  default     = ""
  sensitive   = true
  description = "Si non vide, Falcosidekick envoie Authorization: Bearer … (même valeur que FALCO_WEBHOOK_TOKEN)"
}

variable "grafana_admin_password" {
  type        = string
  default     = "admin"
  sensitive   = true
  description = "Mot de passe Grafana lab (changer hors démonstration)"
}
