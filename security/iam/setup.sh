#!/usr/bin/env bash
# Writes security/iam/.env with the secrets the IAM profile needs. The file is gitignored; nothing secret is committed.
# Run it once before `docker compose --profile iam up`. It refuses to overwrite an existing file unless --force is given.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ -e .env && "${1:-}" != "--force" ]]; then
  echo "security/iam/.env already exists; keeping it (use --force to generate new secrets)"
  exit 0
fi

rand_hex() {   # $1 = number of random bytes
  if command -v openssl >/dev/null 2>&1; then openssl rand -hex "$1"
  else python3 -c "import secrets,sys; print(secrets.token_hex(int(sys.argv[1])))" "$1" 2>/dev/null || python -c "import secrets,sys; print(secrets.token_hex(int(sys.argv[1])))" "$1"
  fi
}

client_secret="$(rand_hex 24)"
umask 077
cat > .env <<ENV
KC_BOOTSTRAP_ADMIN_USERNAME=lab-admin
KC_BOOTSTRAP_ADMIN_PASSWORD=$(rand_hex 12)
CFL_DASHBOARD_CLIENT_SECRET=${client_secret}
OAUTH2_PROXY_CLIENT_SECRET=${client_secret}
OAUTH2_PROXY_COOKIE_SECRET=$(rand_hex 16)
ENV
echo "wrote security/iam/.env (generated secrets, gitignored)"
