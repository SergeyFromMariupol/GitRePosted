#!/usr/bin/env python3
"""Offline packaging/export regression tests. No installed config, DB or provider calls."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).absolute().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = load("package_builder_test", ROOT / "scripts/build.py")
exporter = load("package_exporter_test", ROOT / "scripts/export.py")


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gitreposted-package-test-")
        self.base = Path(self.temporary.name).absolute()
        self.installer, self.runtime = self.base / "installer", self.base / "application"
        for name in builder.INSTALLER_FILES + builder.RUNTIME_TESTS:
            self.write(self.installer / name, b"offline fixture\n")
        for name in builder.RUNTIME_FILES:
            self.write(self.runtime / name, b"offline fixture\n")
        self.write(self.installer / "VERSION", b"0.1.0-rc.1\n")
        package = {"name": "fixture", "type": "module", "scripts": {"start": "node server.js"}, "dependencies": {}}
        lock = {"lockfileVersion": 3, "packages": {"": {"dependencies": {}}}}
        self.write(self.runtime / "package.json", json.dumps(package).encode())
        self.write(self.runtime / "package-lock.json", json.dumps(lock).encode())
        self.write(self.runtime / ".env.example", b"HOST=127.0.0.1\nTELEGRAM_BOT_TOKEN=REPLACE_TOKEN\n")
        self.write(self.runtime / "telegram-bot-api.env.example", b"TELEGRAM_API_HASH=REPLACE_API_HASH\n")

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)

    def export(self, destination=None):
        return exporter.export(self.installer, self.runtime, destination or self.base / "checkout")

    def extract(self, output, destination):
        destination.mkdir()
        with tarfile.open(Path(output["archive"]), "r:gz") as archive:
            archive.extractall(destination, filter="data")
        return destination / builder.PREFIX

    def test_exact_node_allowlist_rejects_legacy_and_private_files(self):
        self.assertTrue(builder.allowed_file("payload/src/server.js"))
        self.assertTrue(builder.allowed_file("payload/src/certs/russiantrustedca.pem"))
        for name in ("payload/src/app.js", "payload/src/index.html", "payload/src/deployment/unit.service",
                     "payload/src/.env", "payload/src/config.php", "payload/src/bootstrap.php",
                     "payload/src/node_modules/anything.js", "tests/unknown.py", "database/schema.sql"):
            self.assertFalse(builder.allowed_file(name), name)
        for name in ("../README.md", "/etc/passwd", "a//b", "a/./b", "a/../b", "a\\b", "X:" + "/file"):
            with self.assertRaises(builder.PackageError):
                builder.allowed_file(name)

    def test_secret_scan_rejects_renamed_tokens_keys_sessions_and_inventory(self):
        values = [b"123456789:" + b"A" * 35, b"ghp_" + b"a" * 40,
                  b"github_pat_" + b"b" * 40, b"-----BEGIN " + b"PRIVATE KEY-----\nfixture",
                  b"SQLite format 3\0fixture", b"PuTTY-User-Key-File-3: fixture\nPrivate-Lines: 1",
                  b"/var/www/" + b"operator/data/secrets/example/application.env",
                  b"X:" + bytes([92]) + b"private/project", b"/project/" + b".codex/private",
                  b"https://max.ru/id" + b"123456789012_bot", b"root@" + b"198.51.100.1",
                  b'"MAX_BOT_TOKEN": "' + b"x" * 40 + b'"']
        for value in values:
            with self.assertRaises(builder.PackageError):
                builder.reject_secret_bytes("README.md", value)
        builder.reject_secret_bytes("payload/src/certs/russiantrustedca.pem", b"-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n")

    def test_sources_read_only_explicit_names_and_do_not_materialize_payload(self):
        trap = self.runtime / "private-config.env"
        self.write(trap, b"must not be read")
        observed = []
        real_read = Path.read_bytes
        def watched(path):
            observed.append(path)
            if path == trap:
                raise AssertionError("Unlisted file was read")
            return real_read(path)
        with patch.object(Path, "read_bytes", watched):
            files = builder.collect_sources(self.installer, self.runtime)
        self.assertNotIn(trap, observed)
        self.assertEqual(set(files), builder.REQUIRED_FILES)
        self.assertFalse((self.installer / "payload").exists())

    def test_invalid_lock_and_filled_example_fail_before_export(self):
        self.write(self.runtime / "package-lock.json", b'{"lockfileVersion":2}')
        with self.assertRaises(exporter.package.PackageError):
            self.export()
        self.assertFalse((self.base / "checkout").exists())
        self.write(self.runtime / "package-lock.json", b'{"lockfileVersion":3,"packages":{"":{"dependencies":{}}}}')
        self.write(self.runtime / ".env.example", b"ADMIN_API_KEY=filled-value\n")
        with self.assertRaises(exporter.package.PackageError):
            self.export()

    def test_documented_commands_and_runtime_imports_must_exist(self):
        self.write(self.installer / "docs/TESTING.md", b"php tests/missing-test.php\n")
        with self.assertRaises(builder.PackageError):
            builder.collect_sources(self.installer, self.runtime)
        self.write(self.installer / "docs/TESTING.md", b"offline fixture\n")
        self.write(self.runtime / "server.js", b'import "./src/missing.js";\n')
        with self.assertRaises(builder.PackageError):
            builder.collect_sources(self.installer, self.runtime)

    def test_distribution_metadata_does_not_modify_application_source(self):
        self.write(self.installer / "README.md", b"first\r\nsecond\r\n")
        package_before = (self.runtime / "package.json").read_bytes()
        lock_before = (self.runtime / "package-lock.json").read_bytes()
        files = builder.collect_sources(self.installer, self.runtime)
        metadata = json.loads(files["payload/src/package.json"])
        self.assertEqual(metadata["license"], "MIT")
        self.assertEqual(metadata["scripts"]["test"], "node --test ../../tests/runtime/*.test.mjs")
        self.assertEqual(files["README.md"], b"first\nsecond\n")
        self.assertEqual((self.installer / "README.md").read_bytes(), b"first\r\nsecond\r\n")
        self.assertEqual(json.loads(files["payload/src/package-lock.json"])["packages"][""]["dependencies"], {})
        self.assertEqual((self.runtime / "package.json").read_bytes(), package_before)
        self.assertEqual((self.runtime / "package-lock.json").read_bytes(), lock_before)

    def test_deterministic_archive_and_strict_manifest(self):
        first = builder.build(self.installer, self.base / "build-a", self.runtime)
        for name in builder.RUNTIME_FILES:
            os.utime(self.runtime / name, (100, 100))
        second = builder.build(self.installer, self.base / "build-b", self.runtime)
        self.assertEqual(first["sha256"], second["sha256"])
        root = self.extract(first, self.base / "extracted")
        self.assertEqual(builder.verify_manifest(root), len(builder.REQUIRED_FILES))
        self.assertFalse(list((root / "payload").rglob("*.php")))
        self.write(root / "README.md", b"tampered\n")
        with self.assertRaises(builder.PackageError):
            builder.verify_manifest(root)

    def test_manifest_rejects_missing_extra_duplicate_and_vcs_files(self):
        result = builder.build(self.installer, self.base / "build", self.runtime)
        for case in ("missing", "extra", "duplicate", "vcs"):
            with self.subTest(case=case):
                root = self.extract(result, self.base / case)
                if case == "missing":
                    (root / "README.md").unlink()
                elif case == "extra":
                    self.write(root / "unlisted.txt", b"extra")
                elif case == "duplicate":
                    marker = root / builder.MANIFEST
                    marker.write_bytes(marker.read_bytes() + marker.read_bytes().splitlines(keepends=True)[0])
                else:
                    self.write(root / ".git" / "HEAD", b"do not read")
                with self.assertRaises(builder.PackageError):
                    builder.verify_manifest(root)

    def test_reexport_preserves_git_and_refuses_edited_or_foreign_files(self):
        self.export()
        checkout = self.base / "checkout"
        self.write(checkout / ".git" / "HEAD", b"preserved-git-metadata")
        self.export()
        self.assertEqual((checkout / ".git" / "HEAD").read_bytes(), b"preserved-git-metadata")
        self.write(checkout / "README.md", b"manual edit")
        with self.assertRaises(exporter.package.PackageError):
            self.export()
        self.assertEqual((checkout / "README.md").read_bytes(), b"manual edit")
        self.write(checkout / "README.md", (self.installer / "README.md").read_bytes())
        self.write(checkout / "foreign.txt", b"foreign content")
        with self.assertRaises(exporter.package.PackageError):
            self.export()
        self.assertEqual((checkout / "foreign.txt").read_bytes(), b"foreign content")

    def test_unmarked_nonempty_destination_is_never_overwritten(self):
        checkout = self.base / "checkout"
        self.write(checkout / "README.md", b"someone else's project")
        with self.assertRaises(exporter.package.PackageError):
            self.export()
        self.assertEqual((checkout / "README.md").read_bytes(), b"someone else's project")

    def test_known_stale_file_removal_is_exact_and_preserves_loader(self):
        optional = builder.OPTIONAL_INSTALLER_FILES[0]
        self.write(self.installer / optional, b"old known test")
        self.export()
        checkout = self.base / "checkout"
        self.write(checkout / "install.sh", b"separately generated loader")
        (self.installer / optional).unlink()
        self.export()
        self.assertFalse((checkout / optional).exists())
        self.assertEqual((checkout / "install.sh").read_bytes(), b"separately generated loader")

    def test_symlink_source_and_destination_are_rejected(self):
        link = self.base / "linked-application"
        try:
            link.symlink_to(self.runtime, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Host does not permit symlink creation")
        with self.assertRaises(builder.PackageError):
            builder.collect_sources(self.installer, link)
        checkout = self.base / "checkout"
        checkout.symlink_to(self.runtime, target_is_directory=True)
        with self.assertRaises(exporter.package.PackageError):
            self.export()


if __name__ == "__main__":
    unittest.main(verbosity=2)
