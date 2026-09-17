resource "helm_release" "kube_prometheus_stack" {
  name             = "kube-prometheus-stack"
  namespace        = "monitoring"
  create_namespace = true

  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "kube-prometheus-stack"

  values = [
    yamlencode({
      grafana = {
        enabled = true

        adminUser     = "admin"
        adminPassword = "admin"

        service = {
          type = "NodePort"
          nodePort = 30030
        }
      }

      prometheus = {
        enabled = true

        service = {
          type = "NodePort"
          nodePort = 30090
        }

        prometheusSpec = {
          scrapeInterval = "5s"
          evaluationInterval = "5s"
          additionalScrapeConfigs = [
            {
              job_name = "devsecops-ai"
              static_configs = [
                {
                  targets = ["192.168.41.128:8000"]
                }
              ]
            }
          ]
        }
      }

      alertmanager = {
        enabled = true
      }

      nodeExporter = {
        enabled = true
      }

      kubeStateMetrics = {
        enabled = true
      }
    })
  ]

  depends_on = [
    kind_cluster.devsecops_lab
  ]
}
