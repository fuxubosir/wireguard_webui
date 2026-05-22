#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export WG_WEBUI_SOURCE_DIR="$SCRIPT_DIR"
exec bash "$SCRIPT_DIR/scripts/uninstall.sh" "$@"
