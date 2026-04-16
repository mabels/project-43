#!/usr/bin/env bash
# Pipeline: our(encrypt) → our(decrypt) → gpg(decrypt)
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

echo "secret message for encrypt-decrypt test" > "$MSG"

# Export card's public key (first fingerprint = signing key, but full cert
# contains the encryption subkey too — that's what we need as recipient).
echo "--- exporting card public key ---"
SIGN_FP=$(gpg --with-colons --card-status 2>/dev/null | awk -F: '/^fpr/{print $2; exit}')
if [ -z "$SIGN_FP" ]; then
    echo "ERROR: could not read key fingerprint from card"; exit 1
fi
gpg --armor --export "$SIGN_FP" > "$RECIPIENT_PUB"
if [ ! -s "$RECIPIENT_PUB" ]; then
    echo "ERROR: public key not in gpg keyring — run: gpg --card-edit (fetch)"; exit 1
fi

echo "--- [1/3] p43 pgp encrypt ---"
"$P43" pgp encrypt --file "$MSG" --recipient "$RECIPIENT_PUB" > "$CIPHER"
cat "$CIPHER"

echo "--- [2/3] p43 pgp decrypt (our decryptor) ---"
gpgconf --kill gpg-agent
"$P43" pgp decrypt --file "$CIPHER" > "$DECRYPTED_OURS"
gpgconf --launch gpg-agent

echo "decrypted (ours): $(cat "$DECRYPTED_OURS")"
diff "$MSG" "$DECRYPTED_OURS"

echo "--- [3/3] gpg --decrypt ---"
gpg --decrypt "$CIPHER" > "$DECRYPTED_GPG"
echo "decrypted (gpg): $(cat "$DECRYPTED_GPG")"
diff "$MSG" "$DECRYPTED_GPG"

echo ""
echo "✓ all three decrypt steps passed"
