#!/usr/bin/env bash
# Pipeline: our(sign) → our(verify) → gpg(verify)
# Requires a physical YubiKey with an OpenPGP key loaded.
set -euo pipefail

P43="${P43:-$(dirname "$0")/../../target/debug/p43}"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

MSG="$TMPDIR/message.txt"
SIG="$TMPDIR/message.sig"
PUB="$TMPDIR/signer.pub.asc"

echo "hello from project-43 sign-verify test" > "$MSG"

# gpg-agent holds exclusive PC/SC access — kill it before card ops
# Export the card's signing public key.
# gpg --with-colons --card-status emits `fpr` records: first is signing key.
echo "--- exporting card public key ---"
SIGN_FP=$(gpg --with-colons --card-status 2>/dev/null | awk -F: '/^fpr/{print $2; exit}')
if [ -z "$SIGN_FP" ]; then
    echo "ERROR: could not read signing fingerprint from card"
    echo "  Make sure pcscd is running and the card is inserted"
    exit 1
fi
echo "  signing fingerprint: $SIGN_FP"
gpg --armor --export "$SIGN_FP" > "$PUB"
if [ ! -s "$PUB" ]; then
    echo "ERROR: public key not in gpg keyring — import it first:"
    echo "  gpg --card-edit  (then type: fetch  quit)"
    exit 1
fi

echo "--- killing gpg-agent ---"
gpgconf --kill gpg-agent

echo "--- [1/3] p43 pgp sign ---"
"$P43" pgp sign --file "$MSG" > "$SIG"
cat "$SIG"

echo "--- restarting gpg-agent ---"
gpgconf --launch gpg-agent

echo "--- [2/3] p43 pgp verify (our verifier) ---"
gpgconf --kill gpg-agent
"$P43" pgp verify --file "$MSG" --sig "$SIG" --signer "$PUB"
gpgconf --launch gpg-agent

echo "--- [3/3] gpg --verify ---"
gpg --verify "$SIG" "$MSG"

echo ""
echo "✓ all three verification steps passed"
