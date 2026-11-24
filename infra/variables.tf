variable "project_id" {
  description = "GCP project ID (set in terraform.tfvars, which is git-ignored)."
  type        = string
}

variable "region" {
  description = "Region for Artifact Registry and Cloud Run. europe-west1 = Belgium, Tier 1 price, covered by the free tier."
  type        = string
  default     = "europe-west1"
}

variable "github_repository" {
  description = "owner/name of the GitHub repo allowed to deploy (used by Workload Identity Federation, step 5)."
  type        = string
  default     = "AhmedKarray005/netsentinel"
}

variable "image_tag" {
  description = "Image tag to deploy (the git commit). Empty = Cloud Run not created yet. CI updates the running images afterwards."
  type        = string
  default     = ""
}

variable "invoker_members" {
  description = "Who may open the app, e.g. [\"user:you@example.com\"] (set in terraform.tfvars, git-ignored). Nobody else, and never allUsers."
  type        = list(string)
  default     = []

  validation {
    condition     = !contains(var.invoker_members, "allUsers") && !contains(var.invoker_members, "allAuthenticatedUsers")
    error_message = "The service must stay private: allUsers / allAuthenticatedUsers are not allowed."
  }
}

variable "max_upload_mb" {
  description = "Upload limit on Cloud Run. Cloud Run rejects HTTP/1 requests over 32 MiB, so it is lower than the local 50 MB."
  type        = number
  default     = 30
}

variable "github_repository_owner_id" {
  description = "Numeric GitHub ID of the repository owner. Checked together with the name, so a deleted-and-recreated account or repo with the same name cannot deploy."
  type        = string
  default     = "104280658"
}

variable "alert_email" {
  description = "Where Cloud Monitoring sends alert emails (set in terraform.tfvars, git-ignored). Empty = no alert policy."
  type        = string
  default     = ""
}
