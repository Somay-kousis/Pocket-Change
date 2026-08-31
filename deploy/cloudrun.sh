#!/usr/bin/env bash
#
# Deploy Pocket Change to Cloud Run: one service serving both the API and the
# console, so there is one URL and no CORS to configure.
#
#   ./deploy/cloudrun.sh
#
# Idempotent. Re-running deploys a new revision and leaves secrets alone.
# Nothing here prints a secret value.

set -euo pipefail

REGION="${REGION:-asia-south1}"          # Mumbai — closest to Razorpay's rails
SERVICE="${SERVICE:-pocket-change}"
# The judgement layers - monitor and critic - already ask for tier="judge";
# this is the only place that says what that tier actually is. Left unset,
# VERTEX_JUDGE_MODEL falls back to the working model and the second opinion
# is produced by the same model that made the decision.
JUDGE_MODEL="${JUDGE_MODEL:-gemini-3.7-flash}"
REPO="${REPO:-pocket-change}"

say()  { printf "\033[1m%s\033[0m\n" "$*"; }
step() { printf "  %s\n" "$*"; }
die()  { printf "\033[31m  %s\033[0m\n" "$*" >&2; exit 1; }

# --- prerequisites ----------------------------------------------------------

command -v gcloud >/dev/null || die "gcloud not found: https://cloud.google.com/sdk"
[ -f .env ] || die ".env not found — the deploy reads your keys from it"

PROJECT="${PROJECT:-$(grep '^GOOGLE_CLOUD_PROJECT=' .env | cut -d= -f2- | tr -d '"'"'"' ')}"
[ -n "$PROJECT" ] || die "GOOGLE_CLOUD_PROJECT is not set in .env"

say "Pocket Change → Cloud Run"
step "project  $PROJECT"
step "region   $REGION"
step "service  $SERVICE"
echo

gcloud projects describe "$PROJECT" >/dev/null 2>&1 \
  || die "cannot reach project $PROJECT — check 'gcloud auth login'"

# Cloud Run needs billing even to use its free tier. Asked over REST rather than
# `gcloud beta billing`, because the beta component is often not installed and a
# missing component should not read as "billing is off".
BILLING="$(curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://cloudbilling.googleapis.com/v1/projects/$PROJECT/billingInfo" \
  | grep -o '"billingEnabled": *true' || true)"

if [ -z "$BILLING" ] && [ -z "${FORCE:-}" ]; then
  echo
  say "Billing does not appear to be enabled on $PROJECT."
  step "Cloud Run needs it even for the free tier:"
  step "https://console.cloud.google.com/billing/linkedaccount?project=$PROJECT"
  if [ -t 0 ]; then
    read -r -p "  Continue anyway? [y/N] " ok
    [ "$ok" = "y" ] || exit 1
  else
    die "refusing to continue without billing (set FORCE=1 to override)"
  fi
fi

# --- APIs -------------------------------------------------------------------

say "1/6  Enabling APIs"
gcloud services enable \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  secretmanager.googleapis.com \
  firestore.googleapis.com \
  aiplatform.googleapis.com \
  --project="$PROJECT" --quiet
step "done"

# --- secrets ----------------------------------------------------------------
#
# Secret Manager rather than --set-env-vars: env vars are legible to anyone with
# console access and turn up in deployment history. These are payment and model
# credentials.

# Cloud Build and the Cloud Run runtime both run as the default compute service
# account, and on a fresh project it holds none of these. Granting them here
# rather than letting the first deploy fail three separate times, which is how
# this was discovered.
say "2/6  Service account roles"
PROJECT_NUMBER="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')"
COMPUTE_SA="$PROJECT_NUMBER-compute@developer.gserviceaccount.com"
for role in \
  roles/storage.objectAdmin \
  roles/logging.logWriter \
  roles/artifactregistry.writer \
  roles/secretmanager.secretAccessor \
  roles/datastore.user \
  roles/aiplatform.user
do
  gcloud projects add-iam-policy-binding "$PROJECT" \
    --member="serviceAccount:$COMPUTE_SA" --role="$role" \
    --condition=None --quiet >/dev/null 2>&1 && step "grant  ${role#roles/}"
done

say "3/6  Secrets"
put_secret() {
  local name="$1" value="$2"
  [ -n "$value" ] || { step "skip   $name (not in .env)"; return; }
  if gcloud secrets describe "$name" --project="$PROJECT" >/dev/null 2>&1; then
    printf '%s' "$value" | gcloud secrets versions add "$name" --data-file=- \
      --project="$PROJECT" --quiet >/dev/null
    step "update $name"
  else
    printf '%s' "$value" | gcloud secrets create "$name" --data-file=- \
      --replication-policy=automatic --project="$PROJECT" --quiet >/dev/null
    step "create $name"
  fi
}

from_env() { grep "^$1=" .env | cut -d= -f2- | tr -d '"'"'"' ' || true; }

put_secret pc-razorpay-key-id     "$(from_env RAZORPAY_KEY_ID)"
put_secret pc-razorpay-key-secret "$(from_env RAZORPAY_KEY_SECRET)"
put_secret pc-gemini-api-key      "$(from_env GEMINI_API_KEY)"
# Already wired in agent/search.py. With it, `best` sourcing reads the real
# web instead of merchant/web_index.py - and the datamarking boundary that
# has only ever seen our own hostile corpus starts seeing real pages.
put_secret pc-tavily-api-key      "$(from_env TAVILY_API_KEY)"

# Fallback providers. Gemini's 15-per-minute free tier is the binding constraint
# on this whole project, and a 429 during judging is the least interesting way
# for a demo to die. All four speak the OpenAI shape; the chain walks past any
# that are down. Measured while wiring this: two of the four already were.
put_secret pc-groq-api-key        "$(from_env GROQ_API_KEY)"
put_secret pc-openrouter-api-key  "$(from_env OPENROUTER_API_KEY)"
put_secret pc-cerebras-api-key    "$(from_env CEREBRAS_API_KEY)"
put_secret pc-sambanova-api-key   "$(from_env SAMBANOVA_API_KEY)"

# The demo token gates writes. Generated once and reused, so a redeploy does not
# invalidate a link you have already shared.
if gcloud secrets describe pc-demo-token --project="$PROJECT" >/dev/null 2>&1; then
  DEMO_TOKEN="$(gcloud secrets versions access latest --secret=pc-demo-token --project="$PROJECT")"
  step "reuse  pc-demo-token"
else
  DEMO_TOKEN="$(head -c 18 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 20)"
  put_secret pc-demo-token "$DEMO_TOKEN"
fi

# The operator token releases held payments, mints mandates and publishes agent
# cards. Unlike the demo token it is never built into the console: whoever
# decides approvals pastes it into their own browser. Generated once and reused.
if gcloud secrets describe pc-operator-token --project="$PROJECT" >/dev/null 2>&1; then
  step "reuse  pc-operator-token"
else
  put_secret pc-operator-token "$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 40)"
fi

# --- registry ---------------------------------------------------------------

say "4/6  Artifact Registry"
if ! gcloud artifacts repositories describe "$REPO" --location="$REGION" --project="$PROJECT" >/dev/null 2>&1; then
  gcloud artifacts repositories create "$REPO" --repository-format=docker \
    --location="$REGION" --project="$PROJECT" --quiet
  step "created $REPO"
else
  step "exists  $REPO"
fi

IMAGE="$REGION-docker.pkg.dev/$PROJECT/$REPO/$SERVICE:$(date +%Y%m%d-%H%M%S)"

# --- build ------------------------------------------------------------------
#
# Built by Cloud Build, so a local Docker daemon is not required.

say "5/6  Building  (a few minutes the first time)"
gcloud builds submit --project="$PROJECT" --region="$REGION" \
  --substitutions="_IMAGE=$IMAGE,_TOKEN=$DEMO_TOKEN" \
  --config=deploy/cloudbuild.yaml .
step "pushed $IMAGE"

# --- deploy -----------------------------------------------------------------

say "6/6  Deploying"
gcloud run deploy "$SERVICE" \
  --image="$IMAGE" \
  --project="$PROJECT" \
  --region="$REGION" \
  --platform=managed \
  --allow-unauthenticated \
  --port=8080 \
  --cpu=1 --memory=1Gi \
  --min-instances=1 --max-instances=3 \
  `# The funnel runs on a background thread after POST /runs has already` \
  `# answered. Cloud Run only guarantees CPU while a request is in flight, so` \
  `# by default it saw an idle instance and shut it down mid-run - the tree` \
  `# simply stopped growing at whatever node it had reached. These two flags` \
  `# are what make a fire-and-watch API viable on serverless: CPU stays on` \
  `# between requests, and one instance is always warm.` \
  --no-cpu-throttling \
  --timeout=600 \
  --set-env-vars="GOOGLE_CLOUD_PROJECT=$PROJECT,POCKETCHANGE_NO_DOTENV=1,POCKETCHANGE_EPHEMERAL_KEYS=1,POCKETCHANGE_VERTEX_LOCATION=$REGION,POCKETCHANGE_VERTEX_JUDGE_MODEL=$JUDGE_MODEL" \
  --set-secrets="RAZORPAY_KEY_ID=pc-razorpay-key-id:latest,RAZORPAY_KEY_SECRET=pc-razorpay-key-secret:latest,GEMINI_API_KEY=pc-gemini-api-key:latest,TAVILY_API_KEY=pc-tavily-api-key:latest,GROQ_API_KEY=pc-groq-api-key:latest,OPENROUTER_API_KEY=pc-openrouter-api-key:latest,CEREBRAS_API_KEY=pc-cerebras-api-key:latest,SAMBANOVA_API_KEY=pc-sambanova-api-key:latest,POCKETCHANGE_DEMO_TOKEN=pc-demo-token:latest,POCKETCHANGE_OPERATOR_TOKEN=pc-operator-token:latest" \
  --quiet

URL="$(gcloud run services describe "$SERVICE" --project="$PROJECT" --region="$REGION" --format='value(status.url)')"

echo
say "Live"
step "console   $URL"
step "health    $URL/status"
step "demo token (needed to start a run):  $DEMO_TOKEN"
step "operator token (approvals, mandates): gcloud secrets versions access latest --secret=pc-operator-token --project=$PROJECT"
echo
step "Reads are open. Starting a run needs that token, which the console"
step "already carries — it is a brake on quota, not authentication."
echo
say "Check it"
step "curl -s $URL/status              # expect rail: razorpay-test"
step "curl -s $URL/counterparties     # open, no token"
