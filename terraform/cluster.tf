provider "kind" {}

resource "kind_cluster" "devsecops_lab" {
  name           = "devsecops-lab"
  wait_for_ready = true

  kind_config {
    kind        = "Cluster"
    api_version = "kind.x-k8s.io/v1alpha4"

    networking {
      disable_default_cni = true
      pod_subnet          = "10.244.0.0/16"
    }

    node {
      role = "control-plane"
    }

    node {
      role = "worker"
    }
  }
}
provider "kubernetes" {
  host                   = kind_cluster.devsecops_lab.endpoint
  cluster_ca_certificate = kind_cluster.devsecops_lab.cluster_ca_certificate
  client_certificate     = kind_cluster.devsecops_lab.client_certificate
  client_key             = kind_cluster.devsecops_lab.client_key
}

provider "helm" {
  kubernetes {
    host                   = kind_cluster.devsecops_lab.endpoint
    cluster_ca_certificate = kind_cluster.devsecops_lab.cluster_ca_certificate
    client_certificate     = kind_cluster.devsecops_lab.client_certificate
    client_key             = kind_cluster.devsecops_lab.client_key
  }
}
