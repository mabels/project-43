#!/usr/bin/env bash
# set-android-secrets.sh
#
# One-shot helper: sets the four Android signing secrets in the GitHub
# Actions "release" environment using the gh CLI.
#
# Usage:
#   1. Fill in the four variables below (or export them beforehand).
#   2. chmod +x scripts/set-android-secrets.sh && ./scripts/set-android-secrets.sh
#
# Requirements: gh CLI authenticated with repo write access.
#   brew install gh && gh auth login
#
# The keystore is read directly from disk so it never appears in your
# shell history.  The other three values are prompted interactively if
# left empty here.

set -euo pipefail

# ── configure these ───────────────────────────────────────────────────────────

# Path to your release keystore file (NOT the base64 string — the raw file).
KEYSTORE_FILE="${KEYSTORE_FILE:-release.keystore}"

# Key alias chosen when you ran keytool -genkey (e.g. "p43").
KEY_ALIAS="${ANDROID_KEY_ALIAS:-}"

# Store password (storePassword in keytool).
STORE_PASSWORD="${ANDROID_STORE_PASSWORD:-}"

# Key password (keyPassword in keytool — often the same as storePassword).
KEY_PASSWORD="${ANDROID_KEY_PASSWORD:-}"

# GitHub environment name (matches what the workflow uses).
GH_ENV="release"

# ── prompt for anything not set ───────────────────────────────────────────────

if [ ! -f "$KEYSTORE_FILE" ]; then
  echo "ERROR: keystore file not found: $KEYSTORE_FILE"
  echo "       Set KEYSTORE_FILE=path/to/release.keystore and re-run."
  exit 1
fi

if [ -z "$KEY_ALIAS" ]; then
  read -rp "Key alias (e.g. p43): " KEY_ALIAS
fi

if [ -z "$STORE_PASSWORD" ]; then
  read -rsp "Store password: " STORE_PASSWORD; echo
fi

if [ -z "$KEY_PASSWORD" ]; then
  read -rsp "Key password (leave blank if same as store password): " KEY_PASSWORD; echo
  KEY_PASSWORD="${KEY_PASSWORD:-$STORE_PASSWORD}"
fi

# ── set secrets ───────────────────────────────────────────────────────────────

echo "Setting ANDROID_KEYSTORE …"
base64 -i "$KEYSTORE_FILE" \
  | gh secret set ANDROID_KEYSTORE --env "$GH_ENV"

echo "Setting ANDROID_STORE_PASSWORD …"
gh secret set ANDROID_STORE_PASSWORD --env "$GH_ENV" --body "$STORE_PASSWORD"

echo "Setting ANDROID_KEY_ALIAS …"
gh secret set ANDROID_KEY_ALIAS --env "$GH_ENV" --body "$KEY_ALIAS"

echo "Setting ANDROID_KEY_PASSWORD …"
gh secret set ANDROID_KEY_PASSWORD --env "$GH_ENV" --body "$KEY_PASSWORD"

echo
echo "Done. Verify at:"
echo "  https://github.com/$(gh repo view --json nameWithOwner -q .nameWithOwner)/settings/environments"
