#!/usr/bin/env bash
# scripts/setup-runner.sh
# Sets up a self-hosted GitHub Actions runner on this Mac.
# Does NOT install a launchd service — start it manually with ./run.sh
#
# Usage:
#   ./scripts/setup-runner.sh <GITHUB_PAT>
#
# The PAT needs the "repo" scope.

set -euo pipefail

PAT="${1:-}"
if [[ -z "$PAT" ]]; then
  echo "Usage: $0 <GITHUB_PAT>" >&2
  exit 1
fi

REPO="mabels/project-43"
RUNNER_DIR="$HOME/actions-runner"
ARCH=$(uname -m)   # arm64 or x86_64

# Map to GitHub's naming convention
case "$ARCH" in
  arm64)   RUNNER_ARCH="arm64" ;;
  x86_64)  RUNNER_ARCH="x64"   ;;
  *)       echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

echo "==> Fetching latest runner version..."
LATEST=$(curl -fsSL \
  -H "Authorization: Bearer $PAT" \
  "https://api.github.com/repos/actions/runner/releases/latest" \
  | grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/')

echo "    version: $LATEST  arch: $RUNNER_ARCH"

TARBALL="actions-runner-osx-${RUNNER_ARCH}-${LATEST}.tar.gz"
URL="https://github.com/actions/runner/releases/download/v${LATEST}/${TARBALL}"

mkdir -p "$RUNNER_DIR"
cd "$RUNNER_DIR"

echo "==> Downloading runner..."
curl -fsSL -o "$TARBALL" "$URL"
tar xzf "$TARBALL"
rm "$TARBALL"

echo "==> Configuring runner (no service install)..."
./config.sh \
  --url "https://github.com/$REPO" \
  --pat "$PAT" \
  --name "$(hostname -s)" \
  --labels "self-hosted,macOS,${RUNNER_ARCH}" \
  --work "_work" \
  --unattended

echo ""
echo "Done. Start the runner with:"
echo "  cd $RUNNER_DIR && ./run.sh"
