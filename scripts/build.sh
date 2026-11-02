#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
: "${IMAGE_TAG:=dev}"
if [[ ! "$IMAGE_TAG" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]]; then
    echo "IMAGE_TAG must be a valid Docker tag." >&2
    exit 1
fi
# Link both GHCR packages to this repository so they inherit its Actions access.
source_url="https://github.com/JeanneBM/devops-platform-lab-local"
for app in pycalculator g4g7singleton; do
    case "$app" in
        pycalculator) context=src/python ;;
        g4g7singleton) context=src/java ;;
    esac
    docker build --label "org.opencontainers.image.source=$source_url" \
        -t "devops-platform-lab-local/$app:$IMAGE_TAG" "$context"
done
