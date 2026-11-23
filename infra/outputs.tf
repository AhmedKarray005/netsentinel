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
