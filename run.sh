#!/usr/bin/env bash
# Author: Junnoh Lee <pluruel@gmail.com>
# Copyright (c) 2026 Junnoh Lee. All rights reserved.
set -euo pipefail

if [ ! -f keys/jwt_private.pem ] || [ ! -f keys/jwt_public.pem ]; then
  echo "JWT keys missing. Generating..."
  cargo run --bin keygen
fi

docker compose -f docker-compose.dev.yaml up --build -d
