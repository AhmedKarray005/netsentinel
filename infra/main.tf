# Foundation: APIs, image registry and the two service accounts.
# Cloud Run (step 4), Workload Identity Federation (step 5) and monitoring (step 6) are added
# in their own files.

locals {
  services = [
    "run.googleapis.com",                  # Cloud Run
    "artifactregistry.googleapis.com",     # Docker image registry
    "iam.googleapis.com",                  # service accounts, Workload Identity Federation
    "iamcredentials.googleapis.com",       # short-lived tokens for GitHub Actions (no keys)
    "sts.googleapis.com",                  # exchanges GitHub's OIDC token for a Google token
    "cloudresourcemanager.googleapis.com", # project-level IAM
    "logging.googleapis.com",
    "monitoring.googleapis.com",
  ]
}

resource "google_project_service" "apis" {
  for_each = toset(local.services)
  service  = each.value

  # `terraform destroy` removes our resources but leaves the APIs on: turning an API off can
  # break other things in the project and has no cost benefit (enabled APIs are free).
  disable_on_destroy = false
}

# ---- Artifact Registry: private Docker repository -------------------------------------------
resource "google_artifact_registry_repository" "images" {
  location      = var.region
  repository_id = "netsentinel"
  format        = "DOCKER"
  description   = "NetSentinel API and dashboard images"

  # Free tier is 0.5 GB: keep the 3 newest versions of each image, delete the rest.
  cleanup_policy_dry_run = false
  cleanup_policies {
    id     = "keep-3-newest"
    action = "KEEP"
    most_recent_versions {
      keep_count = 3
    }
  }
  cleanup_policies {
    id     = "delete-older"
    action = "DELETE"
    condition {
      tag_state  = "ANY"
      older_than = "86400s" # anything older than 1 day that is not among the 3 kept above
    }
  }

  depends_on = [google_project_service.apis]
}

# ---- Service accounts (identities for machines, not people) --------------------------------
# The app's identity on Cloud Run. It gets NO project roles: the API does not call any Google
# service (logs written to stdout are collected by Cloud Run itself).
resource "google_service_account" "run" {
  account_id   = "netsentinel-run"
  display_name = "NetSentinel Cloud Run runtime"
  depends_on   = [google_project_service.apis]
}

# The identity GitHub Actions will use to push images and deploy (step 5).
resource "google_service_account" "deployer" {
  account_id   = "netsentinel-deployer"
  display_name = "NetSentinel GitHub Actions deployer"
  depends_on   = [google_project_service.apis]
}

# Deployer may push images to THIS repository only (not project-wide).
resource "google_artifact_registry_repository_iam_member" "deployer_push" {
  location   = google_artifact_registry_repository.images.location
  repository = google_artifact_registry_repository.images.name
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.deployer.email}"
}

# Deployer may start Cloud Run revisions that run AS the runtime account (on that account only).
resource "google_service_account_iam_member" "deployer_acts_as_run" {
  service_account_id = google_service_account.run.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.deployer.email}"
}

# ---- Default compute service account -------------------------------------------------------
# Google created "<project-number>-compute@developer.gserviceaccount.com" with the Editor role
# (almost full control of the project) when the APIs were enabled. Nothing here uses it: every
# workload runs as its own account above. Removing its Editor role means a misconfigured service
# cannot silently fall back to an over-powerful identity.
# (The account itself was also disabled once with `gcloud iam service-accounts disable`; the
# provider's google_project_default_service_accounts resource found no account to disable here.)
data "google_project" "this" {}

resource "google_project_iam_member_remove" "default_compute_not_editor" {
  project = var.project_id
  role    = "roles/editor"
  member  = "serviceAccount:${data.google_project.this.number}-compute@developer.gserviceaccount.com"
}
