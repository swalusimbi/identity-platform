#!/bin/sh
set -e

# Signing keys must come from the environment. Generating a local
# Ed25519 pair is a development convenience gated behind an explicit
# flag (docker-compose.yml sets it), never a production default.
if [ -z "$JWT_PRIVATE_KEY" ]; then
  if [ "$DEV_GENERATE_KEYS" != "1" ]; then
    echo "ERROR: JWT_PRIVATE_KEY and JWT_PUBLIC_KEY are not configured." >&2
    echo "Provide production signing keys through the environment." >&2
    echo "For local development only, set DEV_GENERATE_KEYS=1 to generate a throwaway pair." >&2
    exit 1
  fi
  mkdir -p /data/keys
  if [ ! -f /data/keys/jwt-private.pem ]; then
    echo "DEV_GENERATE_KEYS=1: generating a development signing pair..."
    openssl genpkey -algorithm Ed25519 -out /data/keys/jwt-private.pem
    openssl pkey -in /data/keys/jwt-private.pem -pubout -out /data/keys/jwt-public.pem
  fi
  JWT_PRIVATE_KEY="$(cat /data/keys/jwt-private.pem)"
  JWT_PUBLIC_KEY="$(cat /data/keys/jwt-public.pem)"
  export JWT_PRIVATE_KEY JWT_PUBLIC_KEY
fi

node dist/db/migrate.js
exec node dist/index.js
