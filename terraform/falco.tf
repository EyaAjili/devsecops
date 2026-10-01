resource "kubernetes_namespace" "falco" {
  metadata {
    name = "falco"
  }
  depends_on = [kind_cluster.devsecops_lab]
}

resource "helm_release" "falco" {
  name            = "falco"
  repository      = "https://falcosecurity.github.io/charts"
  chart           = "falco"
  namespace       = kubernetes_namespace.falco.metadata[0].name
  timeout         = 600
  cleanup_on_fail = true

  # Règles custom : terraform/falco_rules.local.yaml (fichier réellement déployé).
  values = [
    yamlencode({
      customRules = {
        "falco_rules.local.yaml" = file("${path.module}/falco_rules.local.yaml")
      }
    })
  ]

  # eBPF moderne : pas besoin de compiler un module kernel (plus simple en lab Kind).
  set {
    name  = "driver.kind"
    value = "modern_ebpf"
  }

  set {
    name  = "falcosidekick.enabled"
    value = "true"
  }

  # Pas d'UI Falcosidekick (évite Redis + un service de plus). Le webhook suffit.
  set {
    name  = "falcosidekick.webui.enabled"
    value = "false"
  }

  set {
    name  = "tty"
    value = "true"
  }

  # Active le k8s-metacollector pour enrichir les events avec les métadonnées
  # Kubernetes (k8s.pod.name, k8s.ns.name, container.name, etc.)
  set {
    name  = "collectors.kubernetes.enabled"
    value = "true"
  }

  set {
    name  = "falcosidekick.config.webhook.address"
    value = "http://${var.collector_host}:${var.collector_webhook_port}/events"
  }

  dynamic "set" {
    for_each = var.falco_webhook_token == "" ? [] : [1]
    content {
      name  = "falcosidekick.config.webhook.customHeaders"
      value = "Authorization: Bearer ${var.falco_webhook_token}"
    }
  }

  depends_on = [helm_release.cilium]
}
