#!/usr/bin/env bash
set -euo pipefail

# Run from the repository root. OUTPUT_DIR must not already exist, so stale
# archives from another version cannot accidentally enter a release.
if [[ $# -lt 1 || $# -gt 2 ]]; then
  printf 'Usage: bash scripts/package-release.sh VERSION [OUTPUT_DIR]\n' >&2
  exit 2
fi
version=$1
if [[ ! "$version" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]]; then
  printf 'Expected a version such as v1.0.0 or v1.0.0-rc.1\n' >&2
  exit 2
fi

output_dir=${2:-dist}
mkdir "$output_dir"
output_dir=$(cd "$output_dir" && pwd)
package_dir=$(mktemp -d "${TMPDIR:-/tmp}/filecrypt-release.XXXXXX")
trap 'rm -rf "$package_dir"' EXIT

mkdir "$package_dir/spec"
cp LICENSE README.md "$package_dir/"
cp spec/filecrypt-reference-spec.md "$package_dir/spec/"

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  target_os=${target%/*}
  target_arch=${target#*/}
  CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" \
    go build -trimpath -ldflags='-s -w' -o "$package_dir/filecrypt" ./cmd/filecrypt
  # Suppress macOS AppleDouble metadata when packaging locally with BSD tar.
  COPYFILE_DISABLE=1 tar -czf "$output_dir/filecrypt_${version}_${target_os}_${target_arch}.tar.gz" \
    -C "$package_dir" filecrypt LICENSE README.md spec/filecrypt-reference-spec.md
done

(
  cd "$output_dir"
  shasum -a 256 ./*.tar.gz > SHA256SUMS
)
printf 'Release archives and SHA256SUMS written to %s\n' "$output_dir"
