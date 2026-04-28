#!/usr/bin/env bash
#
# One-shot deploy of the PMT-DFC tunnel server to Google Cloud Run.
#
# Idempotent: re-running this script updates the service in place.
#
# Required environment:
#   PROJECT_ID        - GCP project
#   REGION            - e.g. us-central1
#   SERVICE           - e.g. pmt-tunnel
#
# Optional:
#   PMT_AUTH_KEY      - PSK; auto-generated and stored if unset
#   MIN_INSTANCES     - default 1 (kept warm to avoid cold starts)
#   MAX_INSTANCES     - default 4
#
# Pre-reqs: gcloud authenticated, billing enabled, the following APIs on:
#   run.googleapis.com  artifactregistry.googleapis.com
#   secretmanager.googleapis.com  cloudbuild.googleapis.com
#
set -euo pipefail

: "${PROJECT_ID:?PROJECT_ID is required}"
: "${REGION:?REGION is required (e.g. us-central1)}"
: "${SERVICE:?SERVICE is required (e.g. pmt-tunnel)}"

MIN_INSTANCES="${MIN_INSTANCES:-1}"
MAX_INSTANCES="${MAX_INSTANCES:-4}"
SECRET_NAME="pmt-auth-key"
AR_REPO="$SERVICE"
IMAGE="$REGION-docker.pkg.dev/$PROJECT_ID/$AR_REPO/server:latest"

echo ">> enabling required APIs"
gcloud services enable \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  secretmanager.googleapis.com \
  cloudbuild.googleapis.com \
  --project="$PROJECT_ID"

echo ">> ensuring Artifact Registry repo $AR_REPO exists"
if ! gcloud artifacts repositories describe "$AR_REPO" \
    --location="$REGION" --project="$PROJECT_ID" &>/dev/null; then
  gcloud artifacts repositories create "$AR_REPO" \
    --repository-format=docker \
    --location="$REGION" \
    --project="$PROJECT_ID"
fi

echo ">> ensuring Secret Manager entry $SECRET_NAME exists"
if ! gcloud secrets describe "$SECRET_NAME" --project="$PROJECT_ID" &>/dev/null; then
  if [[ -z "${PMT_AUTH_KEY:-}" ]]; then
    PMT_AUTH_KEY="$(openssl rand -base64 48 | tr -d '\n')"
    echo "   (generated a fresh PSK; copy it into your client config NOW)"
    echo "   PMT_AUTH_KEY=$PMT_AUTH_KEY"
  fi
  gcloud secrets create "$SECRET_NAME" \
    --replication-policy=automatic \
    --project="$PROJECT_ID"
  printf '%s' "$PMT_AUTH_KEY" | gcloud secrets versions add "$SECRET_NAME" \
    --data-file=- --project="$PROJECT_ID"
fi

# Grant Cloud Run runtime SA access to the secret. Default SA is fine for now.
PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"
RUNTIME_SA="$PROJECT_NUMBER-compute@developer.gserviceaccount.com"
gcloud secrets add-iam-policy-binding "$SECRET_NAME" \
  --member="serviceAccount:$RUNTIME_SA" \
  --role="roles/secretmanager.secretAccessor" \
  --project="$PROJECT_ID" >/dev/null

echo ">> building image with Cloud Build"
gcloud builds submit \
  --tag="$IMAGE" \
  --project="$PROJECT_ID" \
  --region="$REGION" \
  --machine-type=e2-medium \
  --gcs-log-dir="gs://$PROJECT_ID-cloudbuild-logs/" 2>/dev/null || \
gcloud builds submit \
  --tag="$IMAGE" \
  --project="$PROJECT_ID" \
  .

echo ">> deploying $SERVICE to Cloud Run"
gcloud run deploy "$SERVICE" \
  --image="$IMAGE" \
  --region="$REGION" \
  --platform=managed \
  --allow-unauthenticated \
  --port=8080 \
  --use-http2 \
  --execution-environment=gen2 \
  --cpu=1 \
  --memory=512Mi \
  --concurrency=200 \
  --timeout=3600 \
  --min-instances="$MIN_INSTANCES" \
  --max-instances="$MAX_INSTANCES" \
  --set-env-vars=PMT_LOG_LEVEL=info \
  --set-secrets=PMT_AUTH_KEY="$SECRET_NAME:latest" \
  --no-cpu-throttling \
  --project="$PROJECT_ID"

URL="$(gcloud run services describe "$SERVICE" \
  --region="$REGION" --project="$PROJECT_ID" \
  --format='value(status.url)')"
HOST="${URL#https://}"

echo
echo "============================================================"
echo " Deployed: $URL"
echo " worker_host for client config: $HOST"
echo
echo " Next steps:"
echo "   1. Probe fronting from your network:"
echo "        ./pmt-probe --worker $HOST"
echo "   2. Fill examples/client-config.json with worker_host = $HOST"
echo "      and the PMT_AUTH_KEY value above."
echo "   3. Run pmt-client and point your browser at SOCKS5 127.0.0.1:8085."
echo "============================================================"
