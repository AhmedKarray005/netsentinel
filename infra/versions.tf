# Terraform + Google provider versions, and where the state is kept.
# The state (Terraform's record of what it created) lives in a private, versioned GCS bucket,
# never in Git. The bucket name is given at init time:
#   terraform init -backend-config=backend.hcl     (backend.hcl is git-ignored)
terraform {
  required_version = ">= 1.9"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0, < 8.0"
    }
  }

  backend "gcs" {
    prefix = "netsentinel"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}
