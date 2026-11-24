# Monitoring: an email when the app returns server errors (5xx), and one dashboard.
# Cloud Run reports these metrics by itself; nothing to install in the containers.
# Cost: alerting is free until at least 2027-09-01 (then about $0.35/month for this one
# condition); dashboards and Cloud Run metrics are free.

locals {
  service_filter = "resource.type = \"cloud_run_revision\" AND resource.labels.service_name = \"netsentinel\""
}

resource "google_monitoring_notification_channel" "email" {
  count        = var.alert_email != "" ? 1 : 0
  display_name = "NetSentinel alerts (email)"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
  depends_on = [google_project_service.apis]
}

resource "google_monitoring_alert_policy" "server_errors" {
  count        = var.alert_email != "" && local.deploy ? 1 : 0
  display_name = "NetSentinel: server errors (5xx)"
  combiner     = "OR"

  conditions {
    display_name = "5xx responses on Cloud Run"
    condition_threshold {
      # Every response Cloud Run sends with a 5xx code: crashes in the API, nginx failing to
      # reach the API (502), timeouts (504). Fires on the first one in a 5-minute window.
      filter          = "${local.service_filter} AND metric.type = \"run.googleapis.com/request_count\" AND metric.labels.response_code_class = \"5xx\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
      }
      trigger {
        count = 1
      }
    }
  }

  alert_strategy {
    auto_close = "1800s" # closes by itself 30 min after errors stop
  }

  documentation {
    mime_type = "text/markdown"
    content   = <<-EOT
      NetSentinel on Cloud Run returned server errors.
      Look at the API logs: Logs Explorer, query
      `resource.type="cloud_run_revision" AND resource.labels.service_name="netsentinel" AND severity>=ERROR`
      (each line has a request_id that also appears in the response header X-Request-ID).
    EOT
  }

  notification_channels = [google_monitoring_notification_channel.email[0].id]
}

resource "google_monitoring_dashboard" "app" {
  dashboard_json = jsonencode({
    displayName = "NetSentinel - Cloud Run"
    mosaicLayout = {
      columns = 12
      tiles = [
        {
          width = 6, height = 4
          widget = {
            title = "Requests per minute, by response class (2xx/4xx/5xx)"
            xyChart = {
              dataSets = [{
                plotType   = "STACKED_BAR"
                targetAxis = "Y1"
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "${local.service_filter} AND metric.type = \"run.googleapis.com/request_count\""
                    aggregation = {
                      alignmentPeriod    = "60s"
                      perSeriesAligner   = "ALIGN_SUM"
                      crossSeriesReducer = "REDUCE_SUM"
                      groupByFields      = ["metric.label.response_code_class"]
                    }
                  }
                }
              }]
            }
          }
        },
        {
          xPos = 6, width = 6, height = 4
          widget = {
            title = "Request latency p50 / p95 (ms)"
            xyChart = {
              dataSets = [
                for p in ["50", "95"] : {
                  plotType       = "LINE"
                  targetAxis     = "Y1"
                  legendTemplate = "p${p}"
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "${local.service_filter} AND metric.type = \"run.googleapis.com/request_latencies\""
                      aggregation = {
                        alignmentPeriod    = "60s"
                        perSeriesAligner   = "ALIGN_PERCENTILE_${p}"
                        crossSeriesReducer = "REDUCE_MAX"
                      }
                    }
                  }
                }
              ]
            }
          }
        },
        {
          yPos = 4, width = 6, height = 4
          widget = {
            title = "Memory used, per container (% of limit, p99)"
            xyChart = {
              dataSets = [{
                plotType   = "LINE"
                targetAxis = "Y1"
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "${local.service_filter} AND metric.type = \"run.googleapis.com/container/memory/utilizations\""
                    aggregation = {
                      alignmentPeriod    = "60s"
                      perSeriesAligner   = "ALIGN_PERCENTILE_99"
                      crossSeriesReducer = "REDUCE_MAX"
                      groupByFields      = ["resource.label.container_name"]
                    }
                  }
                }
              }]
            }
          }
        },
        {
          xPos = 6, yPos = 4, width = 6, height = 4
          widget = {
            title = "Running instances (0 = scaled to zero, no cost)"
            xyChart = {
              dataSets = [{
                plotType   = "LINE"
                targetAxis = "Y1"
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "${local.service_filter} AND metric.type = \"run.googleapis.com/container/instance_count\""
                    aggregation = {
                      alignmentPeriod    = "60s"
                      perSeriesAligner   = "ALIGN_MAX"
                      crossSeriesReducer = "REDUCE_MAX"
                    }
                  }
                }
              }]
            }
          }
        },
        {
          yPos = 8, width = 12, height = 4
          widget = {
            title = "API warnings and errors (from the JSON logs)"
            logsPanel = {
              filter = "${local.service_filter} AND severity >= WARNING"
            }
          }
        },
      ]
    }
  })
  depends_on = [google_project_service.apis]
}
