resource "helm_release" "cilium" {
  name       = "cilium"
  repository = "https://helm.cilium.io/"
  chart      = "cilium"
  version    = "1.16.0"
  namespace  = "kube-system"

  set {
    name  = "k8sServiceHost"
    value = "devsecops-lab-control-plane"
  }

  set {
    name  = "k8sServicePort"
    value = "6443"
  }

  depends_on = [kind_cluster.devsecops_lab]
}
