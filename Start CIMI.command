#!/bin/bash
# Double-click this file in Finder to start CIMI and open it in your browser.
cd "$(dirname "$0")" || exit 1
if ! command -v node >/dev/null 2>&1; then
  echo "Node.js is not installed. Download it from https://nodejs.org (version 18 or newer), then double-click this file again."
  read -r -p "Press Enter to close…"
  exit 1
fi
node scripts/launch.js
