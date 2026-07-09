#!/bin/sh
# Generate a fresh Ed25519 signing pair and print it as single line
# .env entries with escaped newlines, ready to paste.
set -e
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

openssl genpkey -algorithm Ed25519 -out "$tmp/private.pem"
openssl pkey -in "$tmp/private.pem" -pubout -out "$tmp/public.pem"

echo "JWT_PRIVATE_KEY=$(awk '{printf "%s\\n", $0}' "$tmp/private.pem")"
echo "JWT_PUBLIC_KEY=$(awk '{printf "%s\\n", $0}' "$tmp/public.pem")"
