"""Remove only expired setup rate counters; preserve sessions and app runtime."""
from __future__ import annotations

import fcntl
import os
from pathlib import Path
import re
import stat
import time

ROOT = Path('/var/lib/gitreposted-installer/sessions')
COUNTER_NAME = re.compile(r'rate-[a-f0-9]{64}\Z')


def cleanup(root: Path = ROOT, *, now: float | None = None) -> int:
    """No client paths are accepted by the CLI; root/clock are test adapters."""
    root = Path(root)
    if not root.is_absolute() or root.name != 'sessions' or root.parent.name != 'gitreposted-installer':
        return 0
    uid = os.getuid()
    ancestors = (root.parent, root)

    def safe_directories() -> bool:
        for directory in ancestors:
            try:
                info = directory.lstat()
                expected_uid = 0 if directory == root.parent else uid
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid
                        or info.st_mode & 0o022 or directory.resolve() != directory):
                    return False
            except (OSError, RuntimeError):
                return False
        return True

    if not safe_directories():
        return 0
    try:
        descriptor = os.open(root / '.rate-cleanup.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError:
        return 0
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077:
            return 0
        try:
            # WizardRateLimit holds this lock shared from before opening a
            # counter until its write is closed, preventing lost fresh counters.
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        deadline = (time.time() if now is None else now) - 300
        removed = 0
        for path in root.iterdir():
            if COUNTER_NAME.fullmatch(path.name) is None:
                continue
            try:
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mtime >= deadline:
                    continue
                if not safe_directories():
                    return removed
                path.unlink()
                removed += 1
            except FileNotFoundError:
                continue
        return removed
    finally:
        os.close(descriptor)


if __name__ == '__main__':
    cleanup()
