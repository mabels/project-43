#!/usr/bin/env bash
# Pipeline: our(sign+encrypt) → our(decrypt+verify) → gpg(decrypt+verify)
# Requires a physical YubiKey with an OpenPGP key loaded.
set -euo pipefail

P43="${P43:-$(dirname "$0")/../../target/debug/p43}"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

MSG="$TMPDIR/plaintext.txt"
CIPHER="$TMPDIR/cipher.asc"
DECRYPTED_OURS="$TMPDIR/decrypted-ours.txt"
DECRYPTED_GPG="$TMPDIR/decrypted-gpg.txt"
RECIPIENT_PUB="$TMPDIR/recipient.pub.asc"
SIGNER_PUB="$TMPDIR/signer.pub.asc"

echo "signed and encrypted message for combined test" > "$MSG"

# Export card's public key — same cert is used as both signer and recipient
echo "--- exporting card public key ---"
SIGN_FP=$(gpg --with-colons --card-status 2>/dev/null | awk -F: '/^fpr/{print $2; exit}')
if [ -z "$SIGN_FP" ]; then
    echo "ERROR: could not read key fingerprint from card"; exit 1
fi
gpg --armor --export "$SIGN_FP" > "$RECIPIENT_PUB"
if [ ! -s "$RECIPIENT_PUB" ]; then
    echo "ERROR: public key not in gpg keyring — run: gpg --card-edit (fetch)"; exit 1
fi
cp "$RECIPIENT_PUB" "$SIGNER_PUB"

echo "--- [1/3] p43 pgp sign-encrypt ---"
gpgconf --kill gpg-agent
"$P43" pgp sign-encrypt --file "$MSG" --recipient "$RECIPIENT_PUB" > "$CIPHER"
gpgconf --launch gpg-agent
cat "$CIPHER"

echo "--- [2/3] p43 pgp decrypt-verify (our impl) ---"
gpgconf --kill gpg-agent
"$P43" pgp decrypt-verify --file "$CIPHER" --signer "$SIGNER_PUB" > "$DECRYPTED_OURS"
gpgconf --launch gpg-agent

echo "decrypted+verified (ours): $(cat "$DECRYPTED_OURS")"
diff "$MSG" "$DECRYPTED_OURS"

echo "--- [3/3] gpg --decrypt (also verifies embedded sig) ---"
gpg --decrypt "$CIPHER" > "$DECRYPTED_GPG"
echo "decrypted+verified (gpg): $(cat "$DECRYPTED_GPG")"
diff "$MSG" "$DECRYPTED_GPG"

echo ""
echo "✓ all three sign+encrypt / decrypt+verify steps passed"
