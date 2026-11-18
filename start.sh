#!/bin/sh
set -eu
cd "$(dirname "$0")"
docker compose build viewer
docker compose run --rm -T setup init
docker compose up -d viewer
printf 'Откройте %s\n' "$(docker compose exec -T viewer printenv PANEL_ORIGIN)"
