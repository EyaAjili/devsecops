resource "kubernetes_namespace" "demo" {
  metadata {
    name = "demo-app"
  }
  depends_on = [kind_cluster.devsecops_lab]
}


resource "kubernetes_deployment" "demo_app" {
  metadata {
    name      = "nginx-demo"
    namespace = kubernetes_namespace.demo.metadata[0].name
    labels = {
      app = "nginx-demo"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "nginx-demo"
      }
    }

    template {
      metadata {
        labels = {
          app = "nginx-demo"
        }
      }

      spec {
        container {
          image = "nginx:latest"
          name  = "nginx"

          port {
            container_port = 80
          }
        }
      }
    }
  }
}
