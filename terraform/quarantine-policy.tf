resource "kubernetes_manifest" "quarantine_policy" {
  manifest = {
    apiVersion = "cilium.io/v2"
    kind       = "CiliumNetworkPolicy"
    metadata = {
      name      = "quarantine-policy"
      namespace = "demo-app"
    }
    spec = {
      endpointSelector = {
        matchLabels = {
          quarantine = "true"
        }
      }
      ingressDeny = [
        {
          fromEntities = ["all"]
        }
      ]
      egressDeny = [
        {
          toEntities = ["all"]
        }
      ]
    }
  }

  depends_on = [
    helm_release.cilium,
    kubernetes_namespace.demo,
  ]
}
