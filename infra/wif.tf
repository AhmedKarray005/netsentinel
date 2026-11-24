# Workload Identity Federation: GitHub Actions deploys WITHOUT any stored key.
#
# 1. A workflow run asks GitHub for an OIDC token ("I am repo X, ref Y, run Z", signed by GitHub).
# 2. Google's STS checks the signature and the condition below, then hands out a short-lived
#    token (1 hour) that may only impersonate netsentinel-deployer.
# Nothing long-lived exists that could leak from GitHub.

resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = "github"
  display_name              = "GitHub Actions"
  description               = "Identities issued by GitHub Actions OIDC"
  depends_on                = [google_project_service.apis]
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-oidc"
  display_name                       = "GitHub OIDC"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  attribute_mapping = {
    "google.subject"                = "assertion.sub"
    "attribute.repository"          = "assertion.repository"
    "attribute.repository_owner_id" = "assertion.repository_owner_id"
    "attribute.ref"                 = "assertion.ref"
  }

  # Only this repository (name + numeric owner ID) and only its main branch. Pull requests,
  # forks, other branches and every other GitHub repository are rejected before any token exists.
  attribute_condition = <<-EOT
    assertion.repository == "${var.github_repository}" &&
    assertion.repository_owner_id == "${var.github_repository_owner_id}" &&
    assertion.ref == "refs/heads/main"
  EOT
}

# Identities that passed the condition may act as the deployer account, and nothing else.
resource "google_service_account_iam_member" "github_impersonates_deployer" {
  service_account_id = google_service_account.deployer.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_repository}"
}

# ---- What the deployer may do on the Cloud Run service (this service only) ------------------
# Roll out new revisions (new image tags).
resource "google_cloud_run_v2_service_iam_member" "deployer_developer" {
  count    = local.deploy ? 1 : 0
  name     = google_cloud_run_v2_service.app[0].name
  location = google_cloud_run_v2_service.app[0].location
  role     = "roles/run.developer"
  member   = "serviceAccount:${google_service_account.deployer.email}"
}

# Call the service once after deploying (health check + a real upload) to prove the new
# revision works. Documented in docs/gcp-deployment.md.
resource "google_cloud_run_v2_service_iam_member" "deployer_smoke_test" {
  count    = local.deploy ? 1 : 0
  name     = google_cloud_run_v2_service.app[0].name
  location = google_cloud_run_v2_service.app[0].location
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.deployer.email}"
}
