output "image_repository" {
  description = "Prefix for image names: <this>/api:<tag> and <this>/web:<tag>."
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.images.repository_id}"
}

output "runtime_service_account" {
  value = google_service_account.run.email
}

output "deployer_service_account" {
  value = google_service_account.deployer.email
}

output "service_url" {
  description = "Private URL (403 without an identity token). Open it through `gcloud run services proxy`."
  value       = local.deploy ? google_cloud_run_v2_service.app[0].uri : null
}

# Values for the GitHub repository variables used by .github/workflows/deploy.yml
# (Settings -> Secrets and variables -> Actions -> Variables). They are identifiers, not secrets:
# without a GitHub OIDC token from this repo's main branch they grant nothing.
output "github_variables" {
  value = {
    GCP_PROJECT_ID        = var.project_id
    GCP_REGION            = var.region
    GCP_WIF_PROVIDER      = google_iam_workload_identity_pool_provider.github.name
    GCP_DEPLOYER_SA       = google_service_account.deployer.email
    GCP_ARTIFACT_REGISTRY = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.images.repository_id}"
  }
}
