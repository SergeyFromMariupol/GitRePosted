#!/usr/bin/env bash
# Publication template. Substitute BOTH literal pins after building the release.
set -euo pipefail
umask 077

BUNDLE_URL='https://github.com/SergeyFromMariupol/GitRePosted/releases/download/v0.1.0-rc.7/gitreposted-installer.tar.gz'
BUNDLE_SHA256='a4f24ef32944de68578efe10098a130abc89961b5013a58798fb819910343fa3'

if [[ ${EUID} -ne 0 ]]; then
  echo 'Run the installer with sudo bash (or as root).' >&2
  exit 1
fi
if [[ ! "$BUNDLE_SHA256" =~ ^[a-f0-9]{64}$ || "$BUNDLE_URL" != https://* || "$BUNDLE_URL" == *'__GITREPOSTED_'* ]]; then
  echo 'This loader has no pinned release. Use the published install.sh.' >&2
  exit 1
fi
for required in curl sha256sum python3 mktemp; do
  if ! command -v "$required" >/dev/null; then
    echo "Required command is unavailable: $required" >&2
    exit 1
  fi
done

temporary="$(mktemp -d /tmp/gitreposted-loader.XXXXXXXX)"
cleanup() {
  # Only this exact private loader directory; never a caller-supplied tree.
  if [[ "$temporary" == /tmp/gitreposted-loader.* && -d "$temporary" && ! -L "$temporary" ]] \
      && [[ "$(realpath -e -- "$temporary")" == "$temporary" ]]; then
    rm -rf -- "$temporary"
  fi
}
trap cleanup EXIT
archive="$temporary/gitreposted-installer.tar.gz"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --connect-timeout 20 --max-time 180 --max-filesize 104857600 \
  --output "$archive" "$BUNDLE_URL"
printf '%s  %s\n' "$BUNDLE_SHA256" "$archive" | sha256sum --check --status

# Reject traversal, links, devices, duplicate names and oversized extraction.
python3 - "$archive" "$temporary" <<'PY'
from pathlib import Path, PurePosixPath
import sys
import tarfile

archive_path, destination = map(Path, sys.argv[1:])
with tarfile.open(archive_path, 'r:gz') as archive:
    members = archive.getmembers()
    if not 1 <= len(members) <= 10000:
        raise SystemExit('Release archive has an unexpected file count.')
    seen, total = set(), 0
    for member in members:
        name = member.name.rstrip('/')
        path = PurePosixPath(name)
        if not name or '\\' in name or any(ord(char) < 32 or ord(char) == 127 for char in name) \
                or path.is_absolute() or str(path) != name or '..' in path.parts \
                or path.parts[0] != 'gitreposted-installer' or name.casefold() in seen \
                or not (member.isfile() or member.isdir()) or getattr(member, 'sparse', None):
            raise SystemExit('Release archive contains an unsafe path or entry.')
        seen.add(name.casefold())
        if member.size < 0 or member.size > 100 * 1024 * 1024:
            raise SystemExit('Release archive contains an oversized file.')
        total += member.size
        if total > 512 * 1024 * 1024:
            raise SystemExit('Release archive is unexpectedly large.')
    archive.extractall(destination, members=members, filter='data')
bundle = destination / 'gitreposted-installer'
for required in ('bootstrap.sh', 'MANIFEST.sha256', 'scripts/build.py'):
    path = bundle / required
    if not path.is_file() or path.is_symlink():
        raise SystemExit('Release archive is incomplete.')
PY

bundle="$temporary/gitreposted-installer"
python3 -B "$bundle/scripts/build.py" --verify-manifest "$bundle"
bash "$bundle/bootstrap.sh" "$@"
