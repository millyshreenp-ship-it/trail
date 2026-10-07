terraform {
  required_version = ">= 1.6"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 6.0" }
  }
}

variable "project_id" {
  type = string
}
variable "zone" {
  type    = string
  default = "asia-south1-a"
}
variable "region" {
  type    = string
  default = "asia-south1"
}
variable "image" {
  type = string
  validation {
    condition     = can(regex("^[a-z0-9-]+-docker\\.pkg\\.dev/[a-z0-9-]+/[a-z0-9-]+/[a-z0-9-]+@sha256:[a-f0-9]{64}$", var.image))
    error_message = "Use an immutable Artifact Registry image digest."
  }
}
variable "registry_repository" {
  type = string
}
variable "master_secret_id" {
  type = string
}
variable "users_secret_id" {
  type = string
}
variable "cors_origin" {
  type = string
  validation {
    condition     = can(regex("^https://[a-zA-Z0-9.-]+$", var.cors_origin))
    error_message = "Use an explicit HTTPS staging origin."
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

resource "google_service_account" "runtime" {
  account_id   = "earlytrace-staging"
  display_name = "EarlyTrace private synthetic staging"
}

resource "google_secret_manager_secret_iam_member" "master" {
  secret_id = var.master_secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime.email}"
}
resource "google_secret_manager_secret_iam_member" "users" {
  secret_id = var.users_secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime.email}"
}
resource "google_artifact_registry_repository_iam_member" "image" {
  location   = var.region
  repository = var.registry_repository
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_compute_network" "private" {
  name                    = "earlytrace-staging"
  auto_create_subnetworks  = false
}
resource "google_compute_subnetwork" "private" {
  name          = "earlytrace-staging"
  ip_cidr_range = "10.71.0.0/24"
  region        = var.region
  network       = google_compute_network.private.id
}
resource "google_compute_router" "egress" {
  name    = "earlytrace-staging-egress"
  region  = var.region
  network = google_compute_network.private.id
}
resource "google_compute_router_nat" "egress" {
  name                               = "earlytrace-staging-egress"
  router                             = google_compute_router.egress.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat  = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}
resource "google_compute_firewall" "iap_ssh" {
  name          = "earlytrace-staging-iap-ssh"
  network       = google_compute_network.private.name
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["earlytrace-staging"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
resource "google_compute_instance" "staging" {
  name         = "earlytrace-staging"
  machine_type = "e2-small"
  tags         = ["earlytrace-staging"]
  boot_disk {
    auto_delete = false
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 20
      type  = "pd-balanced"
    }
  }
  network_interface {
    subnetwork = google_compute_subnetwork.private.id
  }
  service_account {
    email  = google_service_account.runtime.email
    scopes = ["cloud-platform"]
  }
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
  metadata = { "enable-oslogin" = "TRUE", "block-project-ssh-keys" = "TRUE" }
  metadata_startup_script = templatefile("${path.module}/startup.sh", {
    project_id = var.project_id,
    image = var.image,
    master_secret_id = var.master_secret_id,
    users_secret_id = var.users_secret_id,
    cors_origin = var.cors_origin
  })
  depends_on = [google_compute_router_nat.egress, google_secret_manager_secret_iam_member.master, google_secret_manager_secret_iam_member.users, google_artifact_registry_repository_iam_member.image]
}

output "instance" { value = google_compute_instance.staging.name }
output "exposure" { value = "No public IP; SSH through IAP and localhost-only API binding" }