#!/bin/sh
set -e

# Generate a local Ed25519 signing pair on first boot when none is
# configured, so JWKS and local token verification work out of the
# box. The pair persists in the devkeys volume across restarts.
# Anything real must provide its own keys through the environment.
if [ -z "$JWT_PRIVATE_KEY" ]; then
  mkdir -p /data/keys
  if [ ! -f /data/keys/jwt-private.pem ]; then
    echo "No signing keys configured, generating a development pair..."
    openssl genpkey -algorithm Ed25519 -out /data/keys/jwt-private.pem
    openssl pkey -in /data/keys/jwt-private.pem -pubout -out /data/keys/jwt-public.pem
  fi
  JWT_PRIVATE_KEY="$(cat /data/keys/jwt-private.pem)"
  JWT_PUBLIC_KEY="$(cat /data/keys/jwt-public.pem)"
  export JWT_PRIVATE_KEY JWT_PUBLIC_KEY
fi

node dist/db/migrate.js
exec node dist/index.js
