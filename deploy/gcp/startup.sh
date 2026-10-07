#!/bin/bash
set -euo pipefail
umask 077
apt-get update -qq
apt-get install -y -qq docker.io curl jq
systemctl enable --now docker
TOKEN=$(curl -fsS -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token | jq -r '.access_token')
MASTER=$(curl -fsS -H "Authorization: Bearer $TOKEN" 'https://secretmanager.googleapis.com/v1/projects/${project_id}/secrets/${master_secret_id}/versions/latest:access' | jq -r '.payload.data' | base64 -d)
USERS=$(curl -fsS -H "Authorization: Bearer $TOKEN" 'https://secretmanager.googleapis.com/v1/projects/${project_id}/secrets/${users_secret_id}/versions/latest:access' | jq -r '.payload.data' | base64 -d | jq -c '.')
if ! [[ "$MASTER" =~ ^[a-zA-Z0-9_-]{32,256}$ ]]; then exit 1; fi
install -d -o 10001 -g 10001 -m 700 /var/lib/earlytrace
printf 'TRAIL_MASTER_SECRET=%s\nTRAIL_USERS_JSON=%s\n' "$MASTER" "$USERS" > /run/earlytrace.env
printf 'TRAIL_PROFILE=staging\nTRAIL_ENV=staging\nTRAIL_DISABLE_DEV_KEYS=1\nTRAIL_DATA_STATUS=synthetic\nTRAIL_LIVE_INTEGRATIONS=false\nTRAIL_BIND_HOST=0.0.0.0\nTRAIL_CORS_ORIGINS=${cors_origin}\nTRAIL_ASSISTANT_ENABLED=0\n' >> /run/earlytrace.env
DOCKER_CONFIG=$(mktemp -d /run/earlytrace-registry.XXXXXX)
export DOCKER_CONFIG
REGISTRY=$(printf '%s' '${image}' | cut -d/ -f1)
printf '%s' "$TOKEN" | docker login -u oauth2accesstoken --password-stdin "$REGISTRY"
docker pull '${image}'
rm -rf "$DOCKER_CONFIG"
unset TOKEN MASTER USERS
docker rm -f earlytrace-staging 2>/dev/null || true
docker run -d --name earlytrace-staging --restart unless-stopped --read-only --tmpfs /tmp --publish 127.0.0.1:8000:8000 --env-file /run/earlytrace.env --volume /var/lib/earlytrace:/data '${image}'