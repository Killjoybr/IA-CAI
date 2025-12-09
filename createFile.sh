#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    printf 'Usage: %s <text>\n' "$(basename "$0")" >&2
    exit 1
fi

arg="$1"

# ensure the file exists, then append the argument as a new line
touch text.txt
printf '%s\n' "$arg" >> text.txt