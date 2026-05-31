output "cluster_id" {
  description = "LKE cluster ID."
  value       = linode_lke_cluster.nids.id
}

output "cluster_label" {
  description = "LKE cluster label."
  value       = linode_lke_cluster.nids.label
}

output "cluster_status" {
  description = "LKE cluster status."
  value       = linode_lke_cluster.nids.status
}

output "kubeconfig_path" {
  description = "Write the kubeconfig to a file and export KUBECONFIG to use kubectl."
  value       = "Run: terraform output -raw kubeconfig | base64 -d > ~/.kube/nids-linode.yaml && export KUBECONFIG=~/.kube/nids-linode.yaml"
}

output "kubeconfig" {
  description = "Base64-encoded kubeconfig for the LKE cluster."
  value       = linode_lke_cluster.nids.kubeconfig
  sensitive   = true
}

output "api_endpoints" {
  description = "Kubernetes API server endpoints."
  value       = linode_lke_cluster.nids.api_endpoints
}

output "region" {
  description = "Linode region the cluster is deployed in."
  value       = linode_lke_cluster.nids.region
}

output "gpu_pool_id" {
  description = "GPU node pool ID (empty when enable_gpu_pool = false)."
  value       = var.enable_gpu_pool ? linode_lke_node_pool.gpu[0].id : null
}
