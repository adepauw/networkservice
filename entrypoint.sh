#!/usr/bin/env sh
# Run the Network Intelligence wrapper API. It polls the configured sources
# (GL.iNet/OpenWrt) or, if none are configured, runs in mock mode so the CatOS
# Network page is immediately useful.
set -e

exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8103}"
