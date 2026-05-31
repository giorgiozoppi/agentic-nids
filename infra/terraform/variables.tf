variable "linode_token" {
  description = "Linode API personal access token. Set via LINODE_TOKEN env var or TF_VAR_linode_token."
  type        = string
  sensitive   = true
}

variable "region" {
  description = "Linode region for the LKE cluster."
  type        = string
  default     = "eu-west"

  validation {
    condition     = contains(["us-east", "us-ord", "us-sea", "eu-west", "eu-central", "ap-west", "ap-southeast", "ap-northeast"], var.region)
    error_message = "Must be a valid Linode region slug."
  }
}

variable "cluster_label" {
  description = "Unique label for the LKE cluster."
  type        = string
  default     = "agentic-nids"
}

variable "k8s_version" {
  description = "Kubernetes version for the LKE cluster. Run `linode-cli lke versions-list` for available values."
  type        = string
  default     = "1.32"
}

# ── Standard node pool ────────────────────────────────────────────────────────

variable "standard_node_type" {
  description = "Linode instance type for general-purpose workloads (collector, orchestrator, classifier, NATS, ClickHouse)."
  type        = string
  default     = "g6-standard-4"  # 4 vCPU, 8 GB RAM
}

variable "standard_node_count" {
  description = "Number of nodes in the standard pool."
  type        = number
  default     = 3
}

variable "standard_autoscale" {
  description = "Enable autoscaling for the standard node pool."
  type        = bool
  default     = true
}

variable "standard_autoscale_min" {
  type    = number
  default = 2
}

variable "standard_autoscale_max" {
  type    = number
  default = 6
}

# ── ClickHouse node pool ──────────────────────────────────────────────────────

variable "clickhouse_node_type" {
  description = "Linode instance type for ClickHouse StatefulSet (memory-optimised recommended)."
  type        = string
  default     = "g6-highmem-4"  # 4 vCPU, 24 GB RAM
}

variable "clickhouse_node_count" {
  description = "Number of ClickHouse nodes (1 for dev, 3 for HA)."
  type        = number
  default     = 1
}

# ── GPU node pool (vLLM) ──────────────────────────────────────────────────────

variable "enable_gpu_pool" {
  description = "Create a GPU node pool for vLLM (Gemma 4 + DeepSeek). Requires a Linode account with GPU access."
  type        = bool
  default     = false
}

variable "gpu_node_type" {
  description = "Linode GPU instance type. g1-gpu-rtx6000-1 has an RTX 6000 (24 GB VRAM) — sufficient for Gemma 4 27B at fp16."
  type        = string
  default     = "g1-gpu-rtx6000-1"
}

variable "gpu_node_count" {
  description = "Number of GPU nodes. 2 minimum (one per vLLM deployment)."
  type        = number
  default     = 2
}

# ── Tags ──────────────────────────────────────────────────────────────────────

variable "tags" {
  description = "Tags applied to all Linode resources."
  type        = list(string)
  default     = ["agentic-nids"]
}
