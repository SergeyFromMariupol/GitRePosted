#!/usr/bin/env python3
"""Build a deterministic public installer archive; never read production data."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import stat
import tarfile
import tempfile

PREFIX = "gitreposted-installer"
ARCHIVE = PREFIX + ".tar.gz"
MANIFEST = "MANIFEST.sha256"
MAX_FILE_BYTES = 100 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
EXPORT_MARKER = ".gitreposted-export.json"
# Explicit names only. Never copy a private snapshot recursively.
INSTALLER_FILES = (
    "bootstrap.sh", "README.md", "AGENTS.md", "LICENSE", "VERSION", ".gitignore", ".gitattributes",
    "bin/application.php", "bin/cleanup.py", "lib/broker.py", "lib/provision.py", "lib/coinstall.py", "lib/gateway.py", "lib/Wizard.php",
    "web/api.php", "web/index.php", "web/assets/wizard.js", "web/assets/wizard.css",
    "scripts/build.py", "scripts/export.py", "scripts/release-loader.sh", "tests/package_test.py",
    "docs/INSTALLATION.md", "docs/CONFIGURATION.md", "docs/OPERATIONS.md", "docs/SECURITY.md",
    "docs/TESTING.md", "docs/RELEASING.md",
)
OPTIONAL_INSTALLER_FILES = (
    "tests/mounted-gateway-test.py",
    "tests/gateway-test.py", "tests/coinstall-prefix-test.py",
    "tests/coinstall-test.py", "tests/coinstall-provision-test.py", "tests/coinstall-broker-test.py",
    "tests/deep-coinstall-packages-test.py", "tests/deep-coinstall-nginx-test.py", "tests/deep-coinstall-state-test.cjs",
    "tests/application-test.php", "tests/broker-node-test.py", "tests/wizard-node-test.php",
    "tests/wizard-node-ui.test.cjs", "tests/provision-test.py", "tests/provision-audit-test.py",
    "tests/provision-node-test.py",
    "tests/machine-recovery-audit-test.py", "tests/broker_test.py", "tests/broker-review-test.py",
    "tests/cleanup-test.py", "tests/ui.test.cjs", "tests/ui-browser.test.cjs",
    "tests/deep-wizard-ui.test.cjs", "tests/url-consent-test.php", "tests/url-consent.test.cjs",
    "tests/wizard-test.php", "tests/wizard-audit-test.php", "tests/wizard-audit-ui.test.cjs",
)
RUNTIME_FILES = (
    "server.js", "package.json", "package-lock.json", ".env.example", "telegram-bot-api.env.example",
    "src/account-routing.js", "src/account-transfer.js", "src/bot-ui.js", "src/config.js", "src/link-format.js",
    "src/multipart-stream.js", "src/portable-runtime.js", "src/public-base.js", "src/relay-idempotency.js",
    "src/relay-media.js", "src/relay-retry.js", "src/relay-temp-file.js", "src/request-ip.js",
    "src/runtime-secrets.js", "src/security-state.js", "public/index.html", "public/app.js",
    "public/app.css", "public/landing.html", "public/landing.css", "public/landing-strict.css",
    "public/assets/telegram.png", "public/assets/reposted-logo.png", "public/assets/max.png",
    "certs/russiantrustedca.pem",
)
RUNTIME_TESTS = tuple("tests/runtime/" + name + ".test.mjs" for name in (
    "bot-ui", "link-format", "relay-idempotency", "relay-media", "relay-retry", "request-ip",
    "runtime-secrets", "security-state", "streaming-transfer", "portable-runtime", "portable-server",
    "portable-webhook-setup", "mount-prefix", "account-transfer", "account-transfer-ui",
    "account-transfer-relay", "account-route-transfer-races",
))
PUBLIC_FILES = frozenset(INSTALLER_FILES + OPTIONAL_INSTALLER_FILES + RUNTIME_TESTS
                         + tuple("payload/src/" + name for name in RUNTIME_FILES))
REQUIRED_FILES = frozenset(INSTALLER_FILES + RUNTIME_TESTS
                           + tuple("payload/src/" + name for name in RUNTIME_FILES))
PUBLIC_DIRECTORIES = frozenset(str(parent) for name in PUBLIC_FILES
                               for parent in PurePosixPath(name).parents if str(parent) != ".")


class PackageError(ValueError):
    pass


def safe_relative(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if not name or "\\" in name or ":" in name or any(ord(char) < 32 or ord(char) == 127 for char in name) or path.is_absolute() \
            or any(part in {"", ".", ".."} for part in name.split("/")) or str(path) != name:
        raise PackageError("Noncanonical package path")
    return path


def allowed_file(name: str) -> bool:
    safe_relative(name)
    return name in PUBLIC_FILES


def reject_secret_bytes(name: str, value: bytes) -> None:
    # A CA certificate is public; an actual private key or renamed SQLite session is not.
    if re.search(rb"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----", value) or value.startswith(b"SQLite format 3\0") \
            or (value.startswith(b"PuTTY-User-Key-File-") and b"Private-Lines:" in value):
        raise PackageError("Private key/session content is forbidden: " + name)
    if re.search(rb"(?<![A-Za-z0-9])\d{6,12}:[A-Za-z0-9_-]{30,200}(?![A-Za-z0-9_-])", value):
        raise PackageError("Literal Telegram token is forbidden: " + name)
    if re.search(rb"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})", value):
        raise PackageError("Literal GitHub credential is forbidden: " + name)
    for match in re.finditer(rb"['\"](?:bot_token|max_bot_token|telegram_bot_token|api_hash|database_password|db_password|webhook_secret|max_webhook_secret|telegram_webhook_secret|admin_api_key|hcaptcha_secret)['\"]\s*(?:=>|:)\s*['\"]([A-Za-z0-9_:/+.-]{24,})['\"]", value, re.I):
        if not match[1].startswith(b"REPLACE_"):
            raise PackageError("Literal credential value is forbidden: " + name)
    try:
        text_value = value.decode("utf-8")
    except UnicodeError:
        text_value = ""  # Binary assets can contain coincidental path-shaped bytes.
    if re.search(r"/var/www/[^/\s'\"]+/data/(?:www|secrets|data)/", text_value) \
            or re.search(r"(?i)(?<![A-Za-z0-9])[A-Z]:[\\/]", text_value) \
            or re.search(r"(?i)(?:/|\\)\.codex(?:/|\\)", text_value) \
            or re.search(r"(?i)reposted[_-][a-z0-9]*home[_-]bot", text_value) \
            or re.search(r"https://max\.ru/id\d{6,}_bot", text_value) \
            or re.search(r"root@(?:\d{1,3}\.){3}\d{1,3}", text_value):
        raise PackageError("Private deployment inventory is forbidden: " + name)


def linked(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def ordinary_directory(path: Path) -> Path:
    path = path.absolute()
    for component in (path, *path.parents):
        if linked(component) or not component.is_dir():
            raise PackageError("Directory or ancestor is linked/nonordinary")
    if path.resolve(strict=True) != path:
        raise PackageError("Directory path is not canonical")
    return path


def read_public_file(root: Path, name: str) -> bytes:
    path = root
    for part in safe_relative(name).parts:
        path = path / part
        if linked(path):
            raise PackageError("Symlink/reparse point is forbidden: " + name)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_FILE_BYTES:
        raise PackageError("Only bounded ordinary, non-hardlinked files are allowed: " + name)
    value = path.read_bytes()
    if len(value) != info.st_size:
        raise PackageError("Package file changed while building: " + name)
    reject_secret_bytes(name, value)
    return value


def validate_files(files: dict[str, bytes]) -> dict[str, bytes]:
    if any(not allowed_file(name) for name in files):
        raise PackageError("File is outside the public allowlist")
    missing = REQUIRED_FILES - files.keys()
    if missing:
        raise PackageError("Package is incomplete: " + ", ".join(sorted(missing)))
    if sum(map(len, files.values())) > MAX_TOTAL_BYTES:
        raise PackageError("Package is unexpectedly large")
    try:
        package = json.loads(files["payload/src/package.json"])
        lock = json.loads(files["payload/src/package-lock.json"])
        if package.get("type") != "module" or package.get("scripts", {}).get("start") != "node server.js" \
                or lock.get("lockfileVersion") != 3 \
                or package.get("dependencies", {}) != lock.get("packages", {}).get("", {}).get("dependencies", {}):
            raise ValueError()
        for name, entry in lock.get("packages", {}).items():
            if name and (not entry.get("resolved", "").startswith("https://registry.npmjs.org/") or not entry.get("integrity")):
                raise ValueError()
    except (KeyError, ValueError, TypeError, UnicodeError) as error:
        raise PackageError("Node package metadata/lock is inconsistent") from error
    for name in ("payload/src/.env.example", "payload/src/telegram-bot-api.env.example"):
        for line in files[name].decode("utf-8").splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            key, separator, value = line.partition("=")
            if not separator or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
                raise PackageError("Invalid environment example syntax: " + name)
            if re.search(r"(?:TOKEN|PASSWORD|SECRET|API_HASH|ADMIN_API_KEY)$", key) and value and not value.startswith("REPLACE_"):
                raise PackageError("Example credential must be empty or a placeholder: " + name)
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-rc\.\d+)?", files["VERSION"].decode("ascii").strip()):
        raise PackageError("Invalid release version")
    for name, value in files.items():
        if name.startswith("payload/src/") and name.endswith(".js"):
            for target in re.findall(r"(?:from\s*|import\s*)[\"'](\.[^\"']+)[\"']", value.decode("utf-8")):
                resolved = posixpath.normpath(str(PurePosixPath(name).parent / target))
                if resolved not in files or not resolved.startswith("payload/src/"):
                    raise PackageError("Missing/unsafe relative runtime import: " + name)
        if name.endswith(".md"):
            text_value = value.decode("utf-8")
            for target in re.findall(r"\]\(([^\s)]+)\)", text_value):
                if re.match(r"[A-Za-z][A-Za-z0-9+.-]*:", target) or target.startswith("#"):
                    continue
                resolved = posixpath.normpath(str(PurePosixPath(name).parent / target.split("#", 1)[0]))
                if resolved not in files:
                    raise PackageError("Broken public documentation link: " + name)
            for target in re.findall(r"(?<![\w/])(tests/[A-Za-z0-9_./-]+\.(?:php|py|cjs|mjs))", text_value):
                if target not in files:
                    raise PackageError("Missing documented test command: " + target)
    return dict(sorted(files.items()))


def collect_sources(installer: Path, runtime_source: Path) -> dict[str, bytes]:
    """Read explicit names only. No walking of either private source root."""
    installer, runtime_source = ordinary_directory(installer), ordinary_directory(runtime_source)
    files = {name: read_public_file(installer, name) for name in INSTALLER_FILES + RUNTIME_TESTS}
    for name in OPTIONAL_INSTALLER_FILES:
        if (installer / name).exists() or (installer / name).is_symlink():
            files[name] = read_public_file(installer, name)
    files.update({"payload/src/" + name: read_public_file(runtime_source, name) for name in RUNTIME_FILES})
    # Match .gitattributes without changing authoritative source files or binary assets.
    text_suffixes = {".md", ".php", ".py", ".sh", ".js", ".mjs", ".cjs", ".css", ".json", ".pem", ".example"}
    for name, value in files.items():
        if PurePosixPath(name).suffix in text_suffixes or name in {"VERSION", ".gitignore", ".gitattributes"}:
            value.decode("utf-8")  # Invalidly encoded source is not a public text file.
            files[name] = value.replace(b"\r\n", b"\n")
    # Documented distribution-only metadata; preserve all dependency versions/integrity.
    try:
        metadata = json.loads(files["payload/src/package.json"])
        lock = json.loads(files["payload/src/package-lock.json"])
        metadata["license"] = "MIT"
        metadata["scripts"]["test"] = "node --test ../../tests/runtime/*.test.mjs"
        metadata["repository"] = {"type": "git", "url": "git+https://github.com/SergeyFromMariupol/GitRePosted.git"}
        metadata["homepage"] = "https://github.com/SergeyFromMariupol/GitRePosted#readme"
        metadata["bugs"] = {"url": "https://github.com/SergeyFromMariupol/GitRePosted/issues"}
        lock["packages"][""]["license"] = "MIT"
        for name, value in (("package.json", metadata), ("package-lock.json", lock)):
            files["payload/src/" + name] = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    except (KeyError, ValueError, TypeError) as error:
        raise PackageError("Node package metadata cannot be prepared") from error
    return validate_files(files)


def collect(root: Path, *, verify: bool = False) -> dict[str, bytes]:
    root = ordinary_directory(root)
    result: dict[str, bytes] = {}
    seen: set[str] = set()
    total = 0
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        # A normal source checkout is supported without ever reading Git credentials.
        # Extracted release verification still rejects extra VCS metadata.
        if current_path == root and not verify and ".git" in directories:
            if linked(root / ".git"):
                raise PackageError("Linked Git metadata is forbidden")
            directories.remove(".git")
        for child in directories + filenames:
            path = current_path / child
            relative = path.relative_to(root).as_posix()
            safe_relative(relative)
            if linked(path):
                raise PackageError("Symlink/reparse point is forbidden: " + relative)
            if relative in {".git", "install.sh", EXPORT_MARKER} and not verify and path.is_file():
                continue
            if path.is_dir():
                if relative not in PUBLIC_DIRECTORIES:
                    raise PackageError("Directory is outside the public allowlist: " + relative)
                continue
            if not stat.S_ISREG(path.stat().st_mode):
                raise PackageError("Only regular files may be packaged: " + relative)
            if relative == MANIFEST and verify:
                continue
            if not allowed_file(relative):
                raise PackageError("File is outside the public allowlist: " + relative)
            if relative.casefold() in seen:
                raise PackageError("Case-colliding package path: " + relative)
            seen.add(relative.casefold())
            size = path.stat().st_size
            if size > MAX_FILE_BYTES:
                raise PackageError("Oversized package file: " + relative)
            value = read_public_file(root, relative)
            if len(value) != size:
                raise PackageError("Package file changed while building: " + relative)
            total += size
            if total > MAX_TOTAL_BYTES:
                raise PackageError("Package is unexpectedly large")
            reject_secret_bytes(relative, value)
            result[relative] = value
    if not result:
        raise PackageError("Package is empty")
    return validate_files(result)


def manifest_bytes(files: dict[str, bytes]) -> bytes:
    return "".join(hashlib.sha256(value).hexdigest() + "  " + name + "\n" for name, value in sorted(files.items())).encode("utf-8")


def verify_manifest(root: Path) -> int:
    root = root.absolute()
    files = collect(root, verify=True)
    manifest_path = root / MANIFEST
    if not manifest_path.is_file() or linked(manifest_path) or manifest_path.stat().st_size > 4 * 1024 * 1024:
        raise PackageError("Manifest is missing or linked")
    try:
        lines = manifest_path.read_text(encoding="utf-8").splitlines()
    except (UnicodeError, OSError) as error:
        raise PackageError("Manifest is unreadable") from error
    expected: dict[str, str] = {}
    for line in lines:
        matched = re.fullmatch(r"([a-f0-9]{64})  (.+)", line)
        if matched is None:
            raise PackageError("Invalid manifest entry")
        digest, name = matched.groups()
        safe_relative(name)
        if not allowed_file(name) or name in expected:
            raise PackageError("Duplicate or forbidden manifest entry")
        expected[name] = digest
    if set(files) != set(expected):
        raise PackageError("Manifest file set differs from bundle contents")
    for name, value in files.items():
        if hashlib.sha256(value).hexdigest() != expected[name]:
            raise PackageError("Checksum failed: " + name)
    return len(files)


def build(source: Path, output: Path, runtime_source: Path | None = None) -> dict[str, object]:
    source_real = ordinary_directory(source)
    output_real = output.absolute()
    if output_real == source_real or source_real in output_real.parents or output_real in source_real.parents:
        raise PackageError("Output must be outside the installer source tree")
    if runtime_source is not None:
        runtime_real = ordinary_directory(runtime_source)
        if output_real == runtime_real or runtime_real in output_real.parents or output_real in runtime_real.parents:
            raise PackageError("Output must be outside the application source tree")
    files = collect_sources(source_real, runtime_source) if runtime_source is not None else collect(source_real)
    files[MANIFEST] = manifest_bytes(files)
    if output_real.exists():
        ordinary_directory(output_real)
    else:
        ordinary_directory(output_real.parent)
        output_real.mkdir()
    ordinary_directory(output_real)
    archive_path = output_real / ARCHIVE
    checksum_path = output_real / (ARCHIVE + ".sha256")
    if any(path.is_symlink() or (path.exists() and not path.is_file()) for path in (archive_path, checksum_path)):
        raise PackageError("Output target must be an ordinary file")
    descriptor, temporary_value = tempfile.mkstemp(prefix=".gitreposted-installer-", suffix=".tmp", dir=output_real)
    temporary = Path(temporary_value)
    try:
        with os.fdopen(descriptor, "wb") as raw:
            with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0, compresslevel=9) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    directories = {PREFIX}
                    for name in files:
                        directories.update(str(parent) for parent in (PurePosixPath(PREFIX) / name).parents if str(parent) != ".")
                    for name in sorted(directories):
                        entry = tarfile.TarInfo(name + "/")
                        entry.type = tarfile.DIRTYPE
                        entry.mode = 0o755
                        entry.mtime = 0
                        archive.addfile(entry)
                    for name, value in sorted(files.items()):
                        entry = tarfile.TarInfo(PREFIX + "/" + name)
                        entry.mode = 0o755 if name.endswith(".sh") or (name.startswith(("bin/", "scripts/")) and name.endswith(".py")) else 0o644
                        entry.size = len(value)
                        entry.mtime = 0
                        archive.addfile(entry, io.BytesIO(value))
            raw.flush()
            os.fsync(raw.fileno())
        digest = hashlib.sha256(temporary.read_bytes()).hexdigest()
        os.replace(temporary, archive_path)
        # Exact filename only; no recursive cleanup and no files written into source.
        check_descriptor, check_value = tempfile.mkstemp(prefix=".gitreposted-checksum-", suffix=".tmp", dir=output_real)
        check_temporary = Path(check_value)
        try:
            with os.fdopen(check_descriptor, "wb") as check_output:
                check_output.write((digest + "  " + ARCHIVE + "\n").encode("ascii"))
                check_output.flush()
                os.fsync(check_output.fileno())
            os.replace(check_temporary, checksum_path)
        finally:
            check_temporary.unlink(missing_ok=True)
        return {"archive": str(archive_path), "sha256": digest, "file_count": len(files) - 1}
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--output", type=Path, help="Output directory outside INSTALLER")
    action.add_argument("--verify-manifest", type=Path, help="Verify an extracted bundle, including absence of extra files")
    parser.add_argument("--runtime-source", type=Path, help="Explicit application source for a maintainer build")
    arguments = parser.parse_args()
    try:
        if arguments.verify_manifest and arguments.runtime_source:
            raise PackageError("Runtime source is only accepted with --output")
        result = build(Path(__file__).absolute().parents[1], arguments.output, arguments.runtime_source) if arguments.output else {"verified_files": verify_manifest(arguments.verify_manifest)}
        print(json.dumps({"ok": True, "result": result}, ensure_ascii=True))
        return 0
    except (OSError, PackageError, UnicodeError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
