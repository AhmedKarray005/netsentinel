# One Cloud Run service, two containers sharing localhost (like a Kubernetes pod):
#   web (nginx, receives traffic on 8080)  ->  127.0.0.1:8000  ->  api (FastAPI + SQLite)
# Same images as docker compose; nginx is started with its Cloud Run config (see web.Dockerfile).
# Private: only the accounts in var.invoker_members may call it (IAM check before any request
# reaches the containers). Access: `gcloud run services proxy netsentinel --region europe-west1`.

locals {
  deploy    = var.image_tag != ""
  image_api = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.images.repository_id}/api:${var.image_tag}"
  image_web = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.images.repository_id}/web:${var.image_tag}"
}

resource "google_cloud_run_v2_service" "app" {
  count               = local.deploy ? 1 : 0
  name                = "netsentinel"
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_ALL" # reachable from the internet, but IAM still checks every request
  deletion_protection = false                 # so `terraform destroy` can remove it

  template {
    service_account = google_service_account.run.email
    # gen2 = a full Linux kernel. On gen1 (gVisor sandbox) Scapy crashed at import while reading
    # the IPv6 routes over netlink (KeyError: 'scope'), seen on the first deploy (2026-11-23).
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"
    timeout                          = "300s" # a big capture can take a while to analyse
    max_instance_request_concurrency = 10

    scaling {
      min_instance_count = 0 # scale to zero when idle: no cost
      max_instance_count = 1 # SQLite lives in this one instance's memory (see docs/gcp-deployment.md)
    }

    containers {
      name       = "web"
      image      = local.image_web
      args       = ["nginx", "-c", "/etc/nginx/nginx-cloudrun.conf", "-g", "daemon off;"]
      depends_on = ["api"] # nginx starts once the API's startup probe passes

      ports {
        container_port = 8080
      }
      resources {
        limits   = { cpu = "1", memory = "256Mi" }
        cpu_idle = true # CPU only billed while a request is being handled
      }
      startup_probe {
        http_get {
          path = "/healthz"
          port = 8080
        }
      }
    }

    containers {
      name  = "api"
      image = local.image_api

      env {
        name  = "NETSENTINEL_MAX_UPLOAD_MB"
        value = tostring(var.max_upload_mb)
      }
      env {
        name  = "NETSENTINEL_CORS_ORIGINS"
        value = "" # same origin through nginx
      }
      resources {
        limits   = { cpu = "1", memory = "1Gi" } # 1M packets peaked at 228 MB; the upload itself sits in memory too
        cpu_idle = true
      }
      startup_probe {
        http_get {
          path = "/api/health" # runs a database query
          port = 8000
        }
        period_seconds    = 5
        failure_threshold = 24 # up to 2 minutes for a cold start
      }
    }
  }

  lifecycle {
    # After the first deploy, GitHub Actions (step 5) rolls out new images; Terraform must not
    # roll them back on the next apply.
    ignore_changes = [
      template[0].containers[0].image,
      template[0].containers[1].image,
      client,
      client_version,
    ]
  }

  depends_on = [google_project_service.apis]
}

resource "google_cloud_run_v2_service_iam_member" "invokers" {
  for_each = local.deploy ? toset(var.invoker_members) : toset([])
  name     = google_cloud_run_v2_service.app[0].name
  location = google_cloud_run_v2_service.app[0].location
  role     = "roles/run.invoker"
  member   = each.value
}
