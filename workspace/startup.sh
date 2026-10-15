#!/bin/bash
# Startup script for the development server
# Binds to 0.0.0.0:8080 for the preview proxy.

if lsof -Pi :8080 -sTCP:LISTEN -t >/dev/null ; then
    echo "Server already running on port 8080."
    exit 0
fi

# We use PORT=8080 to match the preview proxy requirements
PORT=8080 npm run dev -- --host 0.0.0.0 &
