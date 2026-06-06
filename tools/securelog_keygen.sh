#!/bin/sh
# securelog_keygen.sh
# --------------------
# Generates a 32-byte AES-256 key for the securelog AES provider.
# Saves the key and its SHA-256 hash file alongside.
#
# Usage:
#   ./securelog_keygen.sh [output_path]
#   ./securelog_keygen.sh /etc/securelog/aes.key
#
# Output files:
#   <output_path>         — 32-byte raw AES-256 key (chmod 600)
#   <output_path>.sha256  — SHA-256 hash for integrity verification

set -e

OUTPUT="${1:-aes.key}"
HASHFILE="${OUTPUT}.sha256"

if [ -e "$OUTPUT" ]; then
    echo "[securelog_keygen] ERROR: $OUTPUT already exists. Aborting."
    exit 1
fi

if [ -e "$HASHFILE" ]; then
    echo "[securelog_keygen] ERROR: $HASHFILE already exists. Aborting."
    exit 1
fi

# Generate 32 random bytes (AES-256 key)
openssl rand -out "$OUTPUT" 32
chmod 600 "$OUTPUT"

# Save SHA-256 hash alongside the key
sha256sum "$OUTPUT" > "$HASHFILE"
chmod 600 "$HASHFILE"

echo "[securelog_keygen] Key written to   : $OUTPUT"
echo "[securelog_keygen] Hash written to  : $HASHFILE"
echo ""
echo "[securelog_keygen] SHA-256 fingerprint:"
cat "$HASHFILE"
echo ""
echo "[securelog_keygen] IMPORTANT:"
echo "  - Back up BOTH files securely ($OUTPUT and $HASHFILE)."
echo "  - Without the key, logs cannot be decrypted."
echo "  - The hash file is used by nginx to verify key integrity at startup."
echo "  - Never commit either file to version control."
