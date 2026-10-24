#!/usr/bin/env bash
set -euo pipefail
umask 077
if [[ ${EUID} -ne 0 ]]; then
  echo 'Run: sudo bash bootstrap.sh [--host example.org] [--public-ip IPv4]' >&2
  exit 1
fi
if ! command -v python3 >/dev/null; then
  echo 'Python 3 is required (included in Ubuntu Server 24.04).' >&2
  exit 1
fi
bundle_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
if [[ ! -f "$bundle_dir/lib/provision.py" || ! -f "$bundle_dir/payload/src/server.js" \
      || ! -f "$bundle_dir/payload/src/package.json" || ! -f "$bundle_dir/payload/src/package-lock.json" ]]; then
  echo 'Use the complete release bundle, not a standalone bootstrap.sh.' >&2
  exit 1
fi
# Check ownership without importing any package code. A sudo invocation from a
# user-writable checkout must fail before root runs its build/provision modules.
python3 -I -B - "$bundle_dir" <<'PY'
import os
from pathlib import Path
import stat
import sys

try:
    source = Path(sys.argv[1])
    if not source.is_absolute() or source.resolve(strict=True) != source or not source.is_dir():
        raise ValueError()
    for parent in source.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
            raise ValueError()
    for path in [source, *source.rglob('*')]:
        info = path.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ValueError()
except (OSError, RuntimeError, ValueError):
    sys.exit('The complete package and its ancestors must be root-owned and protected from other users; links are forbidden. Use the release loader or a root-owned checkout.')
PY
if [[ -f "$bundle_dir/MANIFEST.sha256" ]]; then
  (cd -- "$bundle_dir" && sha256sum --check --strict --quiet MANIFEST.sha256)
  python3 -B "$bundle_dir/scripts/build.py" --verify-manifest "$bundle_dir"
fi
exec python3 -B "$bundle_dir/lib/provision.py" "$@"
