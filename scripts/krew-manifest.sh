#!/bin/sh
# Fill plugins/whydied.yaml (a template) from a release checksums.txt.
# Usage: scripts/krew-manifest.sh TAG CHECKSUMS_FILE [TEMPLATE] > whydied.yaml
# Every REPLACE_SHA256_<os>_<arch> placeholder becomes the sha256 of the matching
# archive; the version and download URLs are rewritten for TAG. Fails when a
# checksum is missing, so a manifest with placeholders can never be published.
set -eu

tag=${1:?usage: krew-manifest.sh TAG CHECKSUMS_FILE [TEMPLATE]}
sums=${2:?usage: krew-manifest.sh TAG CHECKSUMS_FILE [TEMPLATE]}
tmpl=${3:-plugins/whydied.yaml}

out=$(grep -v "^ *#" "$tmpl")
out=$(printf '%s\n' "$out" | sed "s#v0\\.1\\.0#${tag}#g")

for platform in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64 windows_amd64 windows_arm64; do
  case $platform in
    windows_*) ext=zip ;;
    *) ext=tar.gz ;;
  esac
  file="kubectl-whydied_${tag}_${platform}.${ext}"
  sum=$(awk -v f="$file" '$2 == f { print $1 }' "$sums")
  if [ -z "$sum" ]; then
    echo "krew-manifest: no checksum for $file in $sums" >&2
    exit 1
  fi
  out=$(printf '%s\n' "$out" | sed "s#REPLACE_SHA256_${platform}#${sum}#")
done

if printf '%s\n' "$out" | grep -q 'REPLACE_SHA256'; then
  echo "krew-manifest: unfilled placeholder left in output" >&2
  exit 1
fi
printf '%s\n' "$out"
