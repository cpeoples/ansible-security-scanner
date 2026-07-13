#!/usr/bin/env bash
# Builds a flat, GPG-signed apt repository under .hugo/static/apt/ so the docs
# Pages deploy serves it at https://cpeoples.github.io/ansible-security-scanner/apt/.
#
# The repo is rebuilt on each release from the .deb files in $DEB_DIR plus any
# .deb already tracked under the pool, so older versions stay installable. The
# public half of the signing key is written to KEY.gpg for users to trust.
#
# Required env:
#   GPG_PRIVATE_KEY   ascii-armored private signing key
#   GPG_KEY_ID        key fingerprint to sign with
# Optional env:
#   DEB_DIR           dir holding freshly built .deb files (default: ./linux)
#   REPO_DIR          output repo root (default: .hugo/static/apt)
#   SUITE             apt suite name (default: stable)
#   COMPONENT         apt component (default: main)
set -euo pipefail

DEB_DIR="${DEB_DIR:-linux}"
REPO_DIR="${REPO_DIR:-.hugo/static/apt}"
SUITE="${SUITE:-stable}"
COMPONENT="${COMPONENT:-main}"
ORIGIN="ansible-security-scanner"

command -v apt-ftparchive >/dev/null || {
  echo "apt-ftparchive not found; install apt-utils" >&2
  exit 1
}
: "${GPG_PRIVATE_KEY:?GPG_PRIVATE_KEY is required}"
: "${GPG_KEY_ID:?GPG_KEY_ID is required}"
GPG_KEY_ID="$(echo "$GPG_KEY_ID" | tr -d '[:space:]')"

pool="${REPO_DIR}/pool/${COMPONENT}"
mkdir -p "$pool"

shopt -s nullglob
new_debs=("${DEB_DIR}"/*.deb)
if [ ${#new_debs[@]} -gt 0 ]; then
  cp -f "${new_debs[@]}" "$pool/"
fi
pool_debs=("$pool"/*.deb)
shopt -u nullglob

if [ ${#pool_debs[@]} -eq 0 ]; then
  echo "no .deb files to publish (looked in $DEB_DIR and $pool)" >&2
  exit 1
fi

# apt-ftparchive writes Filename: fields relative to its working dir, and apt
# resolves package downloads relative to the repo root, so generate the indexes
# from inside REPO_DIR with repo-relative paths (pool/main/...).
archs=$(for deb in "${pool_debs[@]}"; do dpkg-deb -f "$deb" Architecture; done | sort -u)
arch_list=$(echo "$archs" | tr '\n' ' ' | sed 's/ *$//')

cd "$REPO_DIR"
for arch in $archs; do
  bindir="dists/${SUITE}/${COMPONENT}/binary-${arch}"
  mkdir -p "$bindir"
  apt-ftparchive --arch "$arch" packages "pool/${COMPONENT}" > "${bindir}/Packages"
  gzip -9kf "${bindir}/Packages"
done

release_dir="dists/${SUITE}"
apt-ftparchive \
  -o "APT::FTPArchive::Release::Origin=${ORIGIN}" \
  -o "APT::FTPArchive::Release::Label=${ORIGIN}" \
  -o "APT::FTPArchive::Release::Suite=${SUITE}" \
  -o "APT::FTPArchive::Release::Codename=${SUITE}" \
  -o "APT::FTPArchive::Release::Components=${COMPONENT}" \
  -o "APT::FTPArchive::Release::Architectures=${arch_list}" \
  release "$release_dir" > "${release_dir}/Release"

# Bound how long apt trusts this index so a stale mirror can't be frozen
# indefinitely. Appended rather than passed via -o since apt-ftparchive doesn't
# reliably emit Valid-Until across versions.
valid_until="$(date -u -d '+90 days' '+%a, %d %b %Y %H:%M:%S UTC' 2>/dev/null \
  || date -u -v+90d '+%a, %d %b %Y %H:%M:%S UTC')"
printf 'Valid-Until: %s\n' "$valid_until" >> "${release_dir}/Release"

# Sign from a throwaway keyring so the release key never lands in a default one.
gnupg_home="$(mktemp -d)"
trap 'rm -rf "$gnupg_home"' EXIT
export GNUPGHOME="$gnupg_home"
chmod 700 "$gnupg_home"
printf '%s' "$GPG_PRIVATE_KEY" | gpg --batch --import

gpg --batch --yes --local-user "$GPG_KEY_ID" \
  --armor --detach-sign -o "${release_dir}/Release.gpg" "${release_dir}/Release"
gpg --batch --yes --local-user "$GPG_KEY_ID" \
  --clearsign -o "${release_dir}/InRelease" "${release_dir}/Release"

gpg --batch --yes --armor --export "$GPG_KEY_ID" > "KEY.gpg"

echo "apt repo written to ${REPO_DIR} for arch(s): ${arch_list}"
