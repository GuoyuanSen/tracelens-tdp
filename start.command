#!/bin/sh
# macOS launcher. Run from the extracted project directory.
cd "$(dirname "$0")" || exit 1
if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' 'Python 3.9+ is required. Install Python from https://www.python.org/downloads/ and try again.'
  read -r response
  exit 1
fi
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || {
  printf '%s\n' 'Please install Python 3.9 or later.'
  read -r response
  exit 1
}
printf '%s\n' 'Open http://127.0.0.1:8765 in your browser after startup.'
python3 run.py
printf '%s\n' 'TraceLens stopped. Press Return to close.'
read -r response
