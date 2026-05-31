terraform {
  required_version = ">= 1.6"

  required_providers {
    linode = {
      source  = "linode/linode"
      version = "~> 2.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.13"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.30"
    }
  }

  # Remote state — uncomment and configure for team use
  # backend "s3" {
  #   bucket                      = "nids-tfstate"
  #   key                         = "linode/nids.tfstate"
  #   region                      = "us-east-1"
  #   endpoint                    = "https://us-east-1.linodeobjects.com"
  #   skip_credentials_validation = true
  #   skip_metadata_api_check     = true
  #   skip_region_validation      = true
  #   force_path_style            = true
  # }
}
