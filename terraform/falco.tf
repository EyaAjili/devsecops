resource "kubernetes_namespace" "falco" {
  metadata {
    name = "falco"
  }
  depends_on = [kind_cluster.devsecops_lab]
}

resource "helm_release" "falco" {
  name       = "falco"
  repository = "https://falcosecurity.github.io/charts"
  chart      = "falco"
  namespace  = kubernetes_namespace.falco.metadata[0].name

  values = [
    yamlencode({
      customRules = {
        "falco_rules.local.yaml" = file("${path.module}/falco_rules.local.yaml")
      }
    })
  ]

  set {
    name  = "driver.kind"
    value = "modern_ebpf"
  }

  set {
    name  = "falcosidekick.enabled"
    value = "true"
  }

  set {
    name  = "falcosidekick.webui.enabled"
    value = "true"
  }

  set {
    name  = "falcosidekick.webui.redis.persistence.enabled"
    value = "false"
  }

  set {
    name  = "tty"
    value = "true"
  }

  set {
    name  = "falcosidekick.config.webhook.address"
    value = "http://172.17.0.1:5002/events"
  }

  depends_on = [helm_release.cilium]
}
