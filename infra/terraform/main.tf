provider "linode" {
  token = var.linode_token
}

# ── LKE cluster ───────────────────────────────────────────────────────────────

resource "linode_lke_cluster" "nids" {
  label       = var.cluster_label
  region      = var.region
  k8s_version = var.k8s_version
  tags        = var.tags

  # General-purpose pool: collector, orchestrator, classifier, NATS, chatbot, agent
  pool {
    type  = var.standard_node_type
    count = var.standard_node_count

    dynamic "autoscaler" {
      for_each = var.standard_autoscale ? [1] : []
      content {
        min = var.standard_autoscale_min
        max = var.standard_autoscale_max
      }
    }
  }

  # Memory-optimised pool for ClickHouse
  pool {
    type  = var.clickhouse_node_type
    count = var.clickhouse_node_count
  }
}

# ── GPU pool (optional) ───────────────────────────────────────────────────────
# Created as a separate resource so it can be added/removed without recreating
# the cluster.

resource "linode_lke_node_pool" "gpu" {
  count      = var.enable_gpu_pool ? 1 : 0
  cluster_id = linode_lke_cluster.nids.id
  type       = var.gpu_node_type
  node_count = var.gpu_node_count

  labels = {
    "nids/gpu" = "true"
  }

  taints {
    key    = "nids/gpu"
    value  = "true"
    effect = "NoSchedule"
  }
}

# ── Kubernetes provider (uses LKE kubeconfig) ─────────────────────────────────

locals {
  kubeconfig_yaml = base64decode(linode_lke_cluster.nids.kubeconfig)
  kubeconfig_obj  = yamldecode(local.kubeconfig_yaml)
  cluster_host    = local.kubeconfig_obj["clusters"][0]["cluster"]["server"]
  cluster_ca_cert = base64decode(local.kubeconfig_obj["clusters"][0]["cluster"]["certificate-authority-data"])
  cluster_token   = local.kubeconfig_obj["users"][0]["user"]["token"]
}

provider "kubernetes" {
  host                   = local.cluster_host
  cluster_ca_certificate = local.cluster_ca_cert
  token                  = local.cluster_token
}

provider "helm" {
  kubernetes {
    host                   = local.cluster_host
    cluster_ca_certificate = local.cluster_ca_cert
    token                  = local.cluster_token
  }
}

# ── Kubernetes namespaces ─────────────────────────────────────────────────────

resource "kubernetes_namespace" "nids" {
  metadata {
    name = "nids"
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }
}

resource "kubernetes_namespace" "observability" {
  metadata {
    name = "observability"
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }
}

# ── Observability stack (Grafana + Promtail via Helm) ─────────────────────────

resource "helm_release" "observability" {
  name       = "nids-observability"
  chart      = "${path.module}/../../infra/helm/observability"
  namespace  = kubernetes_namespace.observability.metadata[0].name
  atomic     = true
  timeout    = 300

  depends_on = [linode_lke_cluster.nids]
}

# ── NIDS stack (Kustomize applied via kubectl null_resource) ──────────────────
# For full GitOps use ArgoCD or Flux; for simple deploys the local null_resource
# approach is sufficient.

resource "null_resource" "kustomize_apply" {
  triggers = {
    # Re-apply when manifest checksums change.
    k8s_hash = sha256(join("", [
      for f in fileset("${path.module}/../../infra/k8s", "**/*.yaml") :
      filesha256("${path.module}/../../infra/k8s/${f}")
    ]))
  }

  provisioner "local-exec" {
    command = <<-EOT
      export KUBECONFIG=<(echo ${base64encode(local.kubeconfig_yaml)})
      kubectl apply -k ${path.module}/../../infra/k8s/
    EOT
    interpreter = ["/bin/bash", "-c"]
  }

  depends_on = [
    kubernetes_namespace.nids,
    linode_lke_cluster.nids,
  ]
}

# ── Linode Object Storage bucket (optional — for Terraform remote state) ──────
# Uncomment if you want to store tfstate in Linode Object Storage.

# resource "linode_object_storage_bucket" "tfstate" {
#   cluster = "${var.region}-1"
#   label   = "nids-tfstate"
# }
