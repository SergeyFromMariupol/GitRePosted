"""Clean-host bootstrap and bounded provisioning primitives. No production recovery."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
import errno
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import platform
import pwd
import grp
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.parse import urlsplit

VERSION = '0.1.0-rc.3'
INSTALL = Path('/opt/gitreposted-installer')
APP = Path('/opt/gitreposted')
STATE = Path('/var/lib/gitreposted-installer')
DATA = Path('/var/lib/gitreposted')
CONFIG = Path('/etc/gitreposted/config.json')
LOG = Path('/var/log/gitreposted')
ACME = Path('/var/www/gitreposted-acme')
SITE = Path('/etc/nginx/sites-available/gitreposted-installer')
CERTBOT = STATE / 'certbot/bin/certbot'
APP_USER = 'gitreposted'
SETUP_USER = 'gitreposted-setup'
NODE_ROOT = Path('/opt/gitreposted-node')
NODE = NODE_ROOT / 'current/bin/node'
NODE_VERSION = '24.22.1'
# Official release SHASUMS: https://nodejs.org/en/blog/release/v24.22.1
NODE_ARCHIVES = {
    'x86_64': ('x64', '6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6'),
    'aarch64': ('arm64', 'dbabf7a1cbf947e6059ffad2c27b80041db97dea1e553b62afdee7f13fca336e'),
}


class Failure(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def run(argv, *, data=None, timeout=120, safe='Команда системы не выполнена.', capture=True):
    """Never include stdin, raw stderr or argv in raised errors."""
    child = None
    try:
        child = subprocess.Popen([str(x) for x in argv], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE if capture else None, stderr=subprocess.PIPE if capture else None,
                                 start_new_session=True,
                                 env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive', 'LC_ALL': 'C.UTF-8'})
        try:
            output, _ = child.communicate(input=data, timeout=timeout)
        except subprocess.TimeoutExpired:
            # runuser/npm/apt can have descendants. Stop the complete private
            # operation before stage cleanup or a resumable job can begin.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.communicate(timeout=5)
            raise Failure('SYSTEM_COMMAND_FAILED', safe) from None
    except (OSError, subprocess.TimeoutExpired):
        raise Failure('SYSTEM_COMMAND_FAILED', safe) from None
    finally:
        if child is not None:
            if child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None:
                    stream.close()
    if child.returncode:
        raise Failure('SYSTEM_COMMAND_FAILED', safe)
    return output if capture else b''


def identity(name):
    value = pwd.getpwnam(name)
    return value.pw_uid, value.pw_gid


def directory(path, mode=0o750, owner=None):
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path or path.is_symlink():
        raise Failure('UNSAFE_PATH', 'Обнаружена неожиданная символическая ссылка.')
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, mode)
    if owner:
        os.chown(path, *identity(owner))


def atomic(path, content, mode=0o600, uid=0, gid=0):
    path = Path(path)
    if not path.is_absolute() or path.parent.resolve() != path.parent or path.is_symlink() or path.parent.is_symlink():
        raise Failure('UNSAFE_PATH', 'Обнаружен неподходящий путь конфигурации.')
    temporary = path.parent / ('.' + path.name + '.' + secrets.token_hex(8))
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content.encode() if isinstance(content, str) else content)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), uid, gid)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def save_json(path, value, public=False):
    atomic(path, json.dumps(value, ensure_ascii=False, separators=(',', ':')) + '\n',
           0o640 if public else 0o600, 0, identity(SETUP_USER)[1] if public else 0)


def read_json(path, default=None):
    try:
        if Path(path).is_symlink():
            raise Failure('UNSAFE_PATH', 'Небезопасный файл состояния.')
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        return default


def public_ip(value):
    try:
        address = ipaddress.ip_address(value)
        if address.version != 4 or not address.is_global:
            raise ValueError()
        return str(address)
    except ValueError:
        raise Failure('INVALID_IP', 'Нужен публичный IPv4 сервера.') from None


def host_name(value):
    if not isinstance(value, str) or value != value.strip() or len(value) > 253:
        raise Failure('INVALID_HOST', 'Укажите домен без протокола, пути и порта.')
    import re
    value = value.lower()
    try:
        return public_ip(value)
    except Failure:
        pass
    labels = value.split('.')
    if len(labels) < 2 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in labels):
        raise Failure('INVALID_HOST', 'Некорректный домен. Для IDN используйте punycode.')
    if labels[-1].isdigit() or value.endswith(('.local', '.localhost', '.invalid', '.test')):
        raise Failure('INVALID_HOST', 'Нужен публичный домен.')
    return value


def dns_matches(host, ip):
    host = host_name(host)
    if host == ip:
        return
    try:
        addresses = {x[4][0] for x in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
    except OSError:
        raise Failure('DNS_MISMATCH', 'Домен ещё не разрешается. Настройте A-запись и повторите.') from None
    if not addresses or addresses != {ip}:
        raise Failure('DNS_MISMATCH', 'Все A/AAAA-записи домена должны указывать на этот сервер; проверьте также AAAA.')


def detect_ip():
    value = json.loads(run(['ip', '-4', '-j', 'address', 'show', 'scope', 'global']))
    found = set()
    for interface in value:
        for address in interface.get('addr_info', []):
            try:
                found.add(public_ip(address.get('local', '')))
            except Failure:
                pass
    if len(found) != 1:
        raise Failure('PUBLIC_IP_REQUIRED', 'Передайте --public-ip с публичным IPv4 этого сервера.')
    return found.pop()


def preflight(resume=False):
    if os.geteuid() != 0:
        raise Failure('ROOT_REQUIRED', 'Запустите установщик через sudo.')
    values = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if values.get('ID', '').strip('"') != 'ubuntu' or values.get('VERSION_ID', '').strip('"') != '24.04':
        raise Failure('UNSUPPORTED_OS', 'Эта версия установщика поддерживает чистую Ubuntu Server 24.04 LTS.')
    if shutil.disk_usage('/').free < 4 * 1024**3:
        raise Failure('DISK_SPACE', 'Нужно не менее 4 ГиБ свободного места.')
    mem = int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemTotal:')))
    if mem < 900_000:
        raise Failure('MEMORY', 'Нужно не менее 1 ГиБ RAM; рекомендуется 2 ГиБ.')
    node_archive()
    marker = read_json(STATE / 'bootstrap.json')
    if resume:
        if not marker or marker.get('installer') != 'gitreposted-clean-v1' or (STATE / 'installed.json').exists():
            raise Failure('RESUME_UNAVAILABLE', 'Нет незавершённой установки для продолжения.')
        return
    for path in (INSTALL, APP, STATE, DATA, CONFIG.parent, LOG, SITE, NODE_ROOT):
        if path.exists() or path.is_symlink():
            raise Failure('EXISTING_INSTALLATION', 'Обнаружены существующие каталоги GitRePosted. Нужен чистый сервер.')
    for name in (APP_USER, SETUP_USER):
        try:
            pwd.getpwnam(name)
        except KeyError:
            continue
        raise Failure('EXISTING_USER', 'Системный пользователь GitRePosted уже существует.')
    for service in ('nginx', 'apache2', 'mysql', 'mariadb'):
        if shutil.which(service) or Path('/etc/' + service).exists():
            raise Failure('EXISTING_SERVICE', 'На сервере уже есть web-сервер или MySQL. Автоматическая установка остановлена.')
    for port in (80, 443, 3010, 3306):
        for af, addr in ((socket.AF_INET, '0.0.0.0'), (socket.AF_INET6, '::')):
            try:
                with socket.socket(af, socket.SOCK_STREAM) as sock:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    if af == socket.AF_INET6:
                        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    sock.bind((addr, port))
            except OSError as error:
                if error.errno not in (97, 99):
                    raise Failure('PORT_BUSY', 'Порты 80, 443, 3010 или 3306 заняты. Нужен чистый сервер.') from None


def validate_source(source):
    """Audit the complete source before any persistent bootstrap write.

    A root-owned leaf inside somebody else's writable home is not trusted:
    that ancestor could be renamed while root reads the package. Root-owned
    sticky temporary directories are safe for the loader's private root tree.
    """
    source = Path(source)
    try:
        if not source.is_absolute() or source.resolve(strict=True) != source or not source.is_dir():
            raise ValueError()
        for parent in source.parents:
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 \
                    or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
                raise ValueError()
        paths = [source, *sorted(source.rglob('*'))]
        for path in paths:
            info = path.lstat()
            if info.st_uid != 0 or info.st_mode & 0o022 \
                    or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                raise ValueError()
        return paths[1:]
    except (OSError, RuntimeError, ValueError):
        raise Failure('UNSAFE_PACKAGE', 'Пакет и его каталоги должны принадлежать root и быть закрыты от чужой записи; ссылки не разрешены.') from None


def copy_tree(source, target):
    source, target = Path(source), Path(target)
    paths = validate_source(source)
    for path in paths:
        relative = path.relative_to(source)
        destination = target / relative
        if path.is_dir():
            directory(destination, 0o755)
        elif path.is_file():
            directory(destination.parent, 0o755)
            atomic(destination, path.read_bytes(), 0o644)
        else:
            raise Failure('UNSAFE_PACKAGE', 'Пакет содержит необычный файл.')


def package_files(source):
    """Return only the builder's public allowlist, after read-only validation.

    A developer checkout can contain .git credentials; copy_tree must never
    expose that metadata (or an accidentally added private file) under /opt.
    The source has already been proved immutable to non-root before its
    trusted builder module is loaded. No PHP/dependency is needed here.
    """
    source = Path(source)
    validate_source(source)
    try:
        spec = importlib.util.spec_from_file_location('gitreposted_trusted_package_builder', source / 'scripts/build.py')
        if spec is None or spec.loader is None:
            raise ValueError()
        builder = importlib.util.module_from_spec(spec)
        old_bytecode = sys.dont_write_bytecode
        try:
            sys.dont_write_bytecode = True
            spec.loader.exec_module(builder)
        finally:
            sys.dont_write_bytecode = old_bytecode
        has_manifest = (source / 'MANIFEST.sha256').exists()
        if has_manifest:
            builder.verify_manifest(source)
        files = builder.collect(source, verify=has_manifest)
        if has_manifest:
            files['MANIFEST.sha256'] = (source / 'MANIFEST.sha256').read_bytes()
        return files
    except (OSError, ValueError, UnicodeError, SyntaxError):
        raise Failure('INVALID_PACKAGE', 'Пакет неполон или содержит файлы вне публичного списка. Используйте полный проверенный release.') from None


def bundle_members(files):
    """Validate the complete relative namespace before touching the filesystem."""
    members, directories = {}, {Path('.')}
    for name, content in sorted(files.items()):
        if (not isinstance(name, str) or not name or '\\' in name or '\x00' in name
                or any(part in ('', '.', '..') for part in name.split('/'))):
            raise Failure('UNSAFE_PACKAGE', 'Пакет содержит неподходящий относительный путь.')
        relative = Path(*name.split('/'))
        if relative.is_absolute() or relative.drive or not (INSTALL / relative).is_relative_to(INSTALL):
            raise Failure('UNSAFE_PACKAGE', 'Файл пакета находится вне каталога установщика.')
        members[relative] = content
        directories.update(relative.parents)
    if not members or directories.intersection(members):
        raise Failure('UNSAFE_PACKAGE', 'Пути файлов и каталогов пакета пересекаются.')
    return members, directories


def bundle_inventory(root, members, directories):
    """Accept only protected, ordinary entries from this explicit bundle layout.

    A previous interrupted bootstrap may contain a subset of these entries.
    Unknown files are never adopted or deleted, including when the caller is
    retrying from a fresh external release bundle.
    """
    root = Path(root)
    if not root.is_absolute() or root.resolve() != root:
        raise Failure('UNSAFE_PATH', 'Небезопасный каталог установщика.')
    for parent in root.parents:
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX)):
            raise Failure('UNSAFE_PATH', 'Каталоги установщика должны быть защищены от чужой записи.')
    inventory = {}

    def inspect(path, relative):
        info = path.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise Failure('UNSAFE_PATH', 'Файлы установщика должны принадлежать root без чужой записи.')
        if stat.S_ISDIR(info.st_mode) and relative in directories:
            inventory[relative] = ('directory', info.st_dev, info.st_ino)
            for child in path.iterdir():
                inspect(child, relative / child.name)
        elif stat.S_ISREG(info.st_mode) and relative in members and info.st_nlink == 1:
            inventory[relative] = ('file', info.st_dev, info.st_ino)
        else:
            raise Failure('UNSAFE_PATH', 'В каталоге установщика есть посторонний файл или ссылка; автоматическая замена запрещена.')

    inspect(root, Path('.'))
    return inventory


def publish_bundle(stage, replace_existing):
    """Commit one complete directory; never expose a partly copied bundle."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    # RENAME_EXCHANGE preserves the old bundle until the entire replacement is
    # ready. RENAME_NOREPLACE refuses a destination which appeared meanwhile.
    flags = 2 if replace_existing else 1
    if rename(-100, os.fsencode(stage), -100, os.fsencode(INSTALL), flags) != 0:
        raise Failure('BUNDLE_UNAVAILABLE', 'Не удалось атомарно сохранить полный пакет установщика. Повторите внешний загрузчик с --resume.')


def cleanup_bundle_stage(stage, members, directories):
    """Remove only this invocation's exact, allowlisted staging/retired tree."""
    stage = Path(stage)
    if (not stage.is_absolute() or stage.parent != INSTALL.parent or stage.parent.resolve() != stage.parent
            or not stage.name.startswith('.' + INSTALL.name + '-bundle.') or stage.is_symlink()
            or stage.resolve() != stage):
        raise Failure('UNSAFE_PATH', 'Небезопасный временный каталог пакета установщика.')
    inventory = bundle_inventory(stage, members, directories)
    for relative in sorted(inventory, key=lambda item: len(item.parts), reverse=True):
        path = stage / relative
        path.rmdir() if inventory[relative][0] == 'directory' else path.unlink()
    sync_directory(stage.parent)


def persist_bundle(source, files):
    members, directories = bundle_members(files)
    if not INSTALL.is_absolute() or INSTALL.parent.resolve() != INSTALL.parent:
        raise Failure('UNSAFE_PATH', 'Небезопасный путь пакета установщика.')
    for parent in (INSTALL.parent, *INSTALL.parent.parents):
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX)):
            raise Failure('UNSAFE_PATH', 'Каталоги пакета установщика должны быть защищены от чужой записи.')
    existing = bundle_inventory(INSTALL, members, directories) if INSTALL.exists() or INSTALL.is_symlink() else None
    if Path(source).resolve() == INSTALL:
        if existing is None or {name for name, info in existing.items() if info[0] == 'file'} != set(members):
            raise Failure('INVALID_PACKAGE', 'Сохранённый пакет неполон. Повторите внешний загрузчик с --resume.')
        # A validated local resume does not rewrite the code being executed.
        # Repair only public bundle directory traversal left by older releases.
        for relative in sorted(directories, key=lambda item: len(item.parts)):
            directory(INSTALL / relative, 0o755)
        for relative in sorted(directories, key=lambda item: len(item.parts), reverse=True):
            sync_directory(INSTALL / relative)
        return
    stage = Path(tempfile.mkdtemp(prefix='.' + INSTALL.name + '-bundle.', dir=INSTALL.parent))
    published, durable = False, False
    try:
        for relative in sorted(directories - {Path('.')}, key=lambda item: (len(item.parts), str(item))):
            directory(stage / relative, 0o755)
        for relative, content in members.items():
            atomic(stage / relative, content, 0o644)
        directory(stage, 0o755)
        staged = bundle_inventory(stage, members, directories)
        if set(staged) != set(members) | directories:
            raise Failure('INVALID_PACKAGE', 'Временный пакет установщика неполон.')
        for relative in sorted(directories, key=lambda item: len(item.parts), reverse=True):
            sync_directory(stage / relative)
        if existing is not None and bundle_inventory(INSTALL, members, directories) != existing:
            raise Failure('UNSAFE_PATH', 'Сохранённый пакет изменился во время подготовки замены.')
        publish_bundle(stage, existing is not None)
        published = True
        try:
            sync_directory(INSTALL.parent)
        except OSError:
            retained = ' Предыдущий пакет сохранён: ' + str(stage) + '.' if existing is not None else ''
            raise Failure('BUNDLE_UNAVAILABLE', 'Полный пакет опубликован, но сохранение каталога на диск не подтверждено.'
                          + retained + ' Повторите внешний загрузчик с --resume. Сохранённые staging-каталоги автоматически не удаляются.') from None
        durable = True
    finally:
        if stage.exists() or stage.is_symlink():
            # After EXCHANGE this is the previous bundle. Do not destroy
            # it until the parent has durably committed the new directory map.
            # A later external resume never scans or removes these siblings.
            if not (published and not durable and existing is not None):
                cleanup_bundle_stage(stage, members, directories)


def sync_directory(path):
    """Persist directory entries, not only the bytes of their regular files."""
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_initial_state(source, target):
    """Linux no-replace directory commit; an existing path is never adopted."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(source), -100, os.fsencode(target), 1) != 0:  # AT_FDCWD, RENAME_NOREPLACE
        code = ctypes.get_errno()
        if code in (errno.EEXIST, errno.ENOTEMPTY):
            raise Failure('EXISTING_INSTALLATION', 'Каталог состояния уже появился. Не перезаписывайте его; проверьте существующую установку.')
        raise Failure('STATE_UNAVAILABLE', 'Не удалось сохранить начальное состояние установки.')


def initialize_state(ip, host):
    """Publish marker and lock together, so every visible state can resume.

    A killed process before publication may leave an unpublished private
    sibling. It is never adopted or searched for by later installations.
    """
    if STATE.exists() or STATE.is_symlink() or not STATE.is_absolute() or STATE.parent.resolve() != STATE.parent:
        raise Failure('EXISTING_INSTALLATION', 'Каталог состояния уже существует или имеет неожиданный путь.')
    temporary = STATE.parent / ('.' + STATE.name + '-initial.' + secrets.token_hex(8))
    temporary.mkdir(mode=0o700)
    try:
        save_json(temporary / 'bootstrap.json', {'installer': 'gitreposted-clean-v1', 'public_ip': ip, 'host': host})
        descriptor = os.open(temporary / 'installer.lock', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        sync_directory(temporary)
        publish_initial_state(temporary, STATE)
        sync_directory(STATE.parent)
    finally:
        if temporary.exists() and not temporary.is_symlink() and temporary.resolve() == temporary:
            # Only the exact two files this initializer creates; no recursion.
            members = list(temporary.iterdir())
            if any(path.name not in ('bootstrap.json', 'installer.lock') or path.is_symlink() or not path.is_file() for path in members):
                raise Failure('UNSAFE_PATH', 'Временное начальное состояние содержит неожиданный файл.')
            for path in members:
                path.unlink()
            temporary.rmdir()


def php_password(password):
    # Historical broker adapter name; the Node runtime verifies this exact
    # bounded, versioned scrypt format with its built-in crypto implementation.
    salt = secrets.token_hex(16)
    derived = hashlib.scrypt(password.encode('utf-8'), salt=bytes.fromhex(salt), n=16384, r=8, p=1, dklen=32)
    return 'scrypt$16384$8$1$' + salt + '$' + derived.hex()


def enrollment_password(password):
    # PHP's session wizard verifies only this one-time code, never Node's
    # administrator hash. Keep its password_verify contract separate.
    return run(['php', '-r', '$v=json_decode(stream_get_contents(STDIN),true,8,JSON_THROW_ON_ERROR); echo password_hash($v["password"], PASSWORD_DEFAULT);'],
               data=json.dumps({'password': password}).encode(), safe='Не удалось создать одноразовый вход.').decode()


def enrollment():
    private = read_json(STATE / 'private.json', {})
    code = secrets.token_urlsafe(24)
    salt = secrets.token_hex(16)
    private['enrollment'] = {'salt': salt, 'hash': hashlib.pbkdf2_hmac('sha256', code.encode(), salt.encode(), 250000).hex(),
                             'expires_at': int(time.time()) + 86400, 'consumed': False}
    save_json(STATE / 'private.json', private)
    save_json(STATE / 'access.json', {'code_hash': enrollment_password(code), 'expires_at': private['enrollment']['expires_at']}, True)
    return code


def cert_name(host):
    return 'gitreposted-' + hashlib.sha256(host.encode()).hexdigest()[:12]


def obtain_certificate(host, ip, email=''):
    dns_matches(host, ip)
    args = [CERTBOT, 'certonly', '--webroot', '--webroot-path', ACME, '--cert-name', cert_name(host),
            '--non-interactive', '--agree-tos', '--keep-until-expiring', '--preferred-challenges', 'http',
            '--email', email] if email else [CERTBOT, 'certonly', '--webroot', '--webroot-path', ACME,
            '--cert-name', cert_name(host), '--non-interactive', '--agree-tos', '--keep-until-expiring',
            '--preferred-challenges', 'http', '--register-unsafely-without-email']
    if host == ip:
        args += ['--required-profile', 'shortlived', '--ip-address', ip]
    else:
        args += ['-d', host]
    run(args, timeout=300, safe='Не удалось получить TLS-сертификат. Проверьте DNS, доступность 80/443 и ограничения ACME; затем продолжите через --resume.')


def nginx_content(public):
    base_host = host_name(public['host'])
    site_host = host_name(public.get('site_host', base_host))
    installed = public.get('installed', False)
    tls_ready = public.get('tls_ready', False)
    acme = f'location ^~ /.well-known/acme-challenge/ {{ root {ACME}; default_type text/plain; }}'
    status_location = f'location = /install/api.php {{ client_max_body_size 64k; include fastcgi_params; fastcgi_param HTTPS on; fastcgi_param SCRIPT_FILENAME {INSTALL}/web/api.php; fastcgi_read_timeout 50s; fastcgi_pass unix:/run/php/gitreposted-installer.sock; }}'
    wizard = (status_location + '\nlocation = /install { return 404; }\nlocation /install/ { return 404; }' if installed else f'''
location = /install {{ return 302 /install/; }}
location = /install/ {{ include fastcgi_params; fastcgi_param HTTPS on; fastcgi_param SCRIPT_FILENAME {INSTALL}/web/index.php; fastcgi_pass unix:/run/php/gitreposted-installer.sock; }}
{status_location}
location ^~ /install/assets/ {{ alias {INSTALL}/web/assets/; add_header X-Content-Type-Options nosniff always; }}
location /install/ {{ return 404; }}''')
    # Only Node handles application paths. No filesystem root points at source,
    # config, packages or private runtime; forwarded IP is replaced, not trusted.
    proxy = '''proxy_pass http://127.0.0.1:3010;
 proxy_http_version 1.1;
 proxy_set_header Host $host;
 proxy_set_header X-Forwarded-Proto https;
 proxy_set_header X-Forwarded-For $remote_addr;
 proxy_set_header X-Real-IP $remote_addr;
 proxy_set_header Connection "";
 proxy_connect_timeout 5s;
 proxy_read_timeout 60s;'''
    hooks = f'''location = /webhooks/telegram {{ client_max_body_size 2m; {proxy} }}
location = /webhooks/max {{ client_max_body_size 2m; {proxy} }}'''
    private = '''location ~ /\\. { return 404; }
location ~* \\.(?:php|py|sql|gz|ini|log|json|sh|md|pem|lock|env)(?:/|$) { return 404; }
location ~* ^/(?:src|node_modules|certs|secrets|data|runtime|storage|deployment|tools|bin|lib|scripts)(?:/|$) { return 404; }
location = /server.js { return 404; }
location = /app.js.map { return 404; }'''
    app = f'''{hooks}
{private}
location / {{ {proxy} }}'''
    pending_app = f'''{hooks}
{private}
location / {{ return 302 /install/; }}'''
    http = f'''server {{
listen 80 default_server;
server_name _;
{acme}
location / {{ {'return 302 https://' + base_host + '/install/;' if tls_ready and not installed else 'return 301 https://' + site_host + '$request_uri;' if tls_ready else 'default_type text/plain; return 503 "GitRePosted: HTTPS is being configured. Return to the SSH console.\\n";'} }}
}}
'''
    if not tls_ready:
        return http
    servers = []
    for host in dict.fromkeys([base_host, site_host]):
        body = pending_app if not installed else app if host == site_host else f'location / {{ return 302 https://{site_host}$request_uri; }}'
        servers.append(f'''server {{
listen 443 ssl {'default_server' if host == base_host else ''};
server_name {host};
ssl_certificate /etc/letsencrypt/live/{cert_name(host)}/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/{cert_name(host)}/privkey.pem;
ssl_protocols TLSv1.2 TLSv1.3;
client_max_body_size 2m;
add_header X-Content-Type-Options nosniff always;
{wizard}
{body}
}}
''')
    return http + '\n'.join(servers)


def configure_nginx(public):
    old = SITE.read_bytes() if SITE.exists() else None
    atomic(SITE, nginx_content(public), 0o644)
    enabled = Path('/etc/nginx/sites-enabled/gitreposted-installer')
    if not enabled.exists():
        if enabled.is_symlink():
            raise Failure('UNSAFE_PATH', 'Неожиданная конфигурация nginx.')
        enabled.symlink_to(SITE)
    try:
        run(['nginx', '-t'], safe='Новая конфигурация nginx не прошла проверку.')
        run(['systemctl', 'reload', 'nginx'])
    except Failure:
        if old is not None:
            atomic(SITE, old, 0o644)
        raise


def units():
    atomic('/etc/systemd/system/gitreposted-installer.service', f'''[Unit]
Description=GitRePosted temporary installation broker
After=network.target mysql.service php8.3-fpm.service
[Service]
Type=simple
ExecStart=/usr/bin/python3 -B {INSTALL}/lib/broker.py
Restart=on-failure
RestartSec=3
UMask=0077
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=/etc/gitreposted /etc/nginx /var/lib/gitreposted /var/lib/gitreposted-installer /var/log/gitreposted /etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt /run
[Install]
WantedBy=multi-user.target
''', 0o644)
    # Certbot is an isolated dependency of this installer, not the distribution's old version.
    atomic('/etc/systemd/system/gitreposted-cert-renew.service', f'''[Unit]
Description=Renew GitRePosted TLS certificates
[Service]
Type=oneshot
ExecStart={CERTBOT} renew --quiet --deploy-hook "systemctl reload nginx"
''', 0o644)
    atomic('/etc/systemd/system/gitreposted-cert-renew.timer', '''[Unit]
Description=Check GitRePosted certificate renewal twice daily
[Timer]
OnBootSec=10min
OnUnitActiveSec=12h
RandomizedDelaySec=20min
Persistent=true
[Install]
WantedBy=timers.target
''', 0o644)
    # Written during bootstrap, but enabled/started only by the schema job
    # after configuration and local schema initialization have succeeded.
    atomic('/etc/systemd/system/gitreposted-bridge.service', f'''[Unit]
Description=GitRePosted relay bridge
After=network.target mysql.service
Requires=mysql.service
[Service]
Type=simple
User={APP_USER}
Group={APP_USER}
WorkingDirectory={APP}/current/src
Environment=GITREPOSTED_ENV_FILE={CONFIG}
Environment=NODE_EXTRA_CA_CERTS={APP}/current/src/certs/russiantrustedca.pem
ExecStart={NODE} {APP}/current/src/server.js
Restart=always
RestartSec=3
TimeoutStopSec=35
KillMode=control-group
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths={CONFIG.parent} {DATA} {LOG}
[Install]
WantedBy=multi-user.target
''', 0o644)
    atomic('/etc/logrotate.d/gitreposted', f'''{LOG}/*.log {{
 daily
 rotate 14
 compress
 missingok
 notifempty
 copytruncate
 su gitreposted gitreposted
}}
''', 0o644)
    atomic('/etc/systemd/system/gitreposted-rate-limit-cleanup.service', f'''[Unit]
Description=Remove expired GitRePosted installer rate limits
[Service]
Type=oneshot
User={SETUP_USER}
Group={SETUP_USER}
ExecStart=/usr/bin/python3 -B {INSTALL}/bin/cleanup.py
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths={STATE}/sessions
''', 0o644)
    atomic('/etc/systemd/system/gitreposted-rate-limit-cleanup.timer', '''[Unit]
Description=GitRePosted request rate limit cleanup
[Timer]
OnBootSec=5min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
''', 0o644)


def pools():
    for name, user, script_root, session_dir, timeout in (
        ('gitreposted-installer', SETUP_USER, f'{INSTALL}:{STATE}:/tmp', STATE / 'sessions', 60),):
        atomic(f'/etc/php/8.3/fpm/pool.d/{name}.conf', f'''[{name}]
user = {user}
group = {user}
listen = /run/php/{name}.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0600
pm = ondemand
pm.max_children = 4
pm.process_idle_timeout = 15s
request_terminate_timeout = {timeout}s
clear_env = yes
env[GITREPOSTED_ENV_FILE] = {CONFIG}
env[POSTED_INSTALLER_STATE_DIR] = {STATE}
php_admin_value[open_basedir] = {script_root}
php_admin_value[session.save_path] = {session_dir}
php_admin_value[session.gc_probability] = 1
php_admin_value[session.gc_divisor] = 100
php_admin_value[session.gc_maxlifetime] = 3600
php_admin_flag[display_errors] = off
php_admin_flag[log_errors] = on
php_admin_value[error_log] = {LOG / 'php.log' if user == APP_USER else STATE / 'sessions/php.log'}
php_admin_value[upload_max_filesize] = 1M
php_admin_value[post_max_size] = 1M
php_admin_value[max_execution_time] = {timeout}
php_admin_flag[opcache.validate_timestamps] = on
php_admin_value[opcache.revalidate_freq] = 0
php_admin_flag[expose_php] = off
''', 0o644)
    run(['php-fpm8.3', '-t'], safe='Конфигурация PHP-FPM не прошла проверку.')
    run(['systemctl', 'restart', 'php8.3-fpm'])


@contextmanager
def installer_lock():
    path = STATE / 'installer.lock'
    if STATE.resolve() != STATE or STATE.is_symlink() or path.is_symlink():
        raise Failure('UNSAFE_PATH', 'Небезопасный путь блокировки установщика.')
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_uid != 0 or info.st_mode & 0o077:
            raise Failure('UNSAFE_PATH', 'Блокировка установщика должна принадлежать root с режимом 0600.')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Failure('INSTALL_BUSY', 'Установка уже выполняется. Дождитесь завершения задания.') from None
        yield
    finally:
        os.close(fd)


def show_link(host, code):
    print('\nOpen this personal one-time link:\nhttps://' + host + '/install/#setup=' + code
          + '\nThe browser signs in automatically. The fragment is not sent in the HTTP URL. Keep this link private.', flush=True)


def reconcile_installed():
    """Repair the terminal state after a crash following the durable marker.

    The caller holds installer.lock (or is the broker's current job owner).
    This never starts services, changes application config or reopens enrollment.
    """
    marker_path = STATE / 'installed.json'
    if not marker_path.exists() and not marker_path.is_symlink():
        return False
    if STATE.resolve() != STATE or STATE.is_symlink():
        raise Failure('UNSAFE_PATH', 'Небезопасный каталог состояния установщика.')
    marker = read_json(marker_path)
    if not isinstance(marker, dict) or type(marker.get('installed_at')) is not int or marker['installed_at'] <= 0 \
            or not isinstance(marker.get('version'), str) or not 1 <= len(marker['version']) <= 100 \
            or not isinstance(marker.get('admin_url'), str):
        raise Failure('STATE_CONFLICT', 'Некорректная отметка завершённой установки; автоматическое продолжение запрещено.')
    try:
        url = urlsplit(marker['admin_url'])
        host = host_name(url.netloc)
    except (Failure, ValueError):
        raise Failure('STATE_CONFLICT', 'Некорректный адрес завершённой установки.') from None
    if url.scheme != 'https' or url.netloc != host or url.path != '/control/' or url.query or url.fragment:
        raise Failure('STATE_CONFLICT', 'Некорректный адрес завершённой установки.')
    public = read_json(STATE / 'public.json', {})
    private = read_json(STATE / 'private.json', {})
    if not isinstance(public, dict) or not isinstance(private, dict):
        raise Failure('STATE_CONFLICT', 'Состояние завершённой установки недоступно.')
    job = public.get('job', {})
    if not isinstance(job, dict):
        job = {}
    job = {**job, 'type': 'install', 'status': 'complete', 'error': None}
    steps = job.get('steps', [])
    job['steps'] = [{**step, 'status': 'skipped' if step.get('status') == 'skipped' else 'done'}
                    for step in steps if isinstance(step, dict)] if isinstance(steps, list) else []
    public.update({'installed': True, 'admin_url': marker['admin_url'], 'version': marker['version'],
                   'site_url': 'https://' + host, 'site_host': host, 'job': job})
    for key in ('settings', 'config', 'enrollment', 'job', 'public_state', 'bot_bindings'):
        private.pop(key, None)
    # Remove duplicate credentials before publishing terminal public metadata.
    # Every step is idempotent if another crash interrupts this reconciliation.
    save_json(STATE / 'private.json', private)
    access = STATE / 'access.json'
    if access.is_symlink():
        raise Failure('UNSAFE_PATH', 'Небезопасный файл доступа установщика.')
    access.unlink(missing_ok=True)
    save_json(STATE / 'public.json', public, True)
    return True


def reconcile_pending_finish(public):
    """Reopen the wizard if nginx closed before the final marker was committed.

    The final nginx reload and installed.json are separate external effects.
    Until the marker exists, a killed finish step must remain retryable through
    the browser. Never reopen a committed installation or touch app config.
    """
    marker = STATE / 'installed.json'
    if not isinstance(public, dict) or public.get('installed') is True or public.get('tls_ready') is not True \
            or marker.exists() or marker.is_symlink():
        return False
    job = public.get('job', {})
    if not isinstance(job, dict) or job.get('type') != 'install':
        return False
    steps = job.get('steps', [])
    finish = [step for step in steps if isinstance(step, dict) and step.get('id') == 'finish'] if isinstance(steps, list) else []
    if len(finish) != 1 or finish[0].get('status') not in ('running', 'failed', 'done'):
        return False
    configure_nginx({**public, 'installed': False})
    return True


def resume_ready():
    if reconcile_installed():
        return True
    public = read_json(STATE / 'public.json', {})
    if public.get('installed') or (STATE / 'installed.json').exists():
        raise Failure('RESUME_UNAVAILABLE', 'Установка завершена, мастер закрыт.')
    if public.get('tls_ready') is not True:
        private = read_json(STATE / 'private.json', {})
        if any(private.get(key) for key in ('settings', 'config', 'job')):
            raise Failure('STATE_CONFLICT', 'Установка приложения уже начата. Не переустанавливайте инфраструктуру; проверьте состояние задания.')
        return False
    reconcile_pending_finish(public)
    # Reissue enrollment only. Never copy code, reset public metadata, restart
    # an active job or replace application/configuration during --resume.
    code = enrollment()
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', 'gitreposted-installer.service', 'gitreposted-cert-renew.timer', 'gitreposted-rate-limit-cleanup.timer'])
    show_link(host_name(public['host']), code)
    return True


def node_archive():
    selected = NODE_ARCHIVES.get(platform.machine())
    if selected is None:
        raise Failure('UNSUPPORTED_ARCH', 'Поддерживаются Ubuntu 24.04 x86_64 и arm64.')
    arch, digest = selected
    return 'node-v' + NODE_VERSION + '-linux-' + arch, digest


def clean_stage(path, parent, prefix):
    """Remove only our exact canonical staging directory, without following links."""
    path, parent = Path(path), Path(parent)
    if (not path.is_absolute() or parent.resolve() != parent or path.parent != parent
            or not path.name.startswith(prefix) or path.is_symlink() or path.resolve() != path):
        raise Failure('UNSAFE_PATH', 'Небезопасный временный каталог установки.')
    if path.exists():
        shutil.rmtree(path)


def extract_node(archive_path, destination, prefix):
    """Validate even the pinned vendor archive before its privileged extraction."""
    with tarfile.open(archive_path, 'r:xz') as archive:
        members = archive.getmembers()
        if not 1 <= len(members) <= 20000:
            raise Failure('INVALID_NODE_ARCHIVE', 'Архив Node.js не прошёл проверку.')
        seen, total = set(), 0
        for member in members:
            name = member.name.rstrip('/')
            relative = PurePosixPath(name)
            if (not name or '\\' in name or any(ord(char) < 32 or ord(char) == 127 for char in name)
                    or relative.is_absolute() or str(relative) != name or '..' in relative.parts
                    or relative.parts[0] != prefix or name in seen or member.size < 0
                    or member.size > 200 * 1024 * 1024 or getattr(member, 'sparse', None)
                    or not (member.isfile() or member.isdir() or member.issym())):
                raise Failure('INVALID_NODE_ARCHIVE', 'Архив Node.js не прошёл проверку.')
            seen.add(name)
            if member.issym():
                # Vendor npm/npx links are relative and must stay in this tree.
                if '\\' in member.linkname or PurePosixPath(member.linkname).is_absolute():
                    raise Failure('INVALID_NODE_ARCHIVE', 'Архив Node.js содержит неподходящую ссылку.')
                target = (Path(destination) / name).parent / member.linkname
                if not target.resolve().is_relative_to(Path(destination) / prefix):
                    raise Failure('INVALID_NODE_ARCHIVE', 'Архив Node.js содержит внешнюю ссылку.')
            total += member.size
            if total > 512 * 1024 * 1024:
                raise Failure('INVALID_NODE_ARCHIVE', 'Архив Node.js слишком большой.')
        archive.extractall(destination, members=members, filter='data')


def normalize_node_tree(root):
    """Open only root-owned vendor directories; never follow a vendor link.

    tarfile's data filter deliberately drops directory modes. With bootstrap's
    umask 077 those directories become 0700, even if the binary is executable.
    Restore public traversal on the verified vendor tree, preserving all file
    modes. Resolve relative npm links against a metadata map, without opening
    their targets or ever walking outside this tree.
    """
    root = Path(root)
    if not root.is_absolute() or root.is_symlink() or root.resolve() != root:
        raise Failure('UNSAFE_PATH', 'Каталог Node.js должен быть каноническим обычным каталогом.')
    entries, links = {(): 'directory'}, {}

    def walk(descriptor, relative):
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Failure('UNSAFE_PATH', 'Каталоги Node.js должны принадлежать root без чужой записи.')
        os.fchmod(descriptor, 0o755)
        for name in os.listdir(descriptor):
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            current = relative + (name,)
            if stat.S_ISDIR(info.st_mode):
                entries[current] = 'directory'
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                try:
                    walk(child, current)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                if info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1:
                    raise Failure('UNSAFE_PATH', 'Node.js содержит неподтверждённый файл.')
                entries[current] = 'file'
            elif stat.S_ISLNK(info.st_mode):
                target = os.readlink(name, dir_fd=descriptor)
                if (info.st_uid != 0 or not target or '\\' in target or PurePosixPath(target).is_absolute()
                        or any(ord(char) < 32 or ord(char) == 127 for char in target)):
                    raise Failure('UNSAFE_PATH', 'Node.js содержит неподходящую ссылку.')
                entries[current], links[current] = 'link', target
            else:
                raise Failure('UNSAFE_PATH', 'Node.js содержит специальный файл.')

    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        walk(descriptor, ())
    finally:
        os.close(descriptor)
    for link, target in links.items():
        pending, resolved, followed = [*link[:-1], *target.split('/')], [], 0
        while pending:
            part = pending.pop(0)
            if part in ('', '.'):
                continue
            if part == '..':
                if not resolved:
                    raise Failure('UNSAFE_PATH', 'Ссылка Node.js выходит за каталог версии.')
                resolved.pop()
                continue
            current = (*resolved, part)
            kind = entries.get(current)
            if kind is None:
                raise Failure('UNSAFE_PATH', 'Ссылка Node.js не имеет подтверждённой цели.')
            if kind == 'link':
                followed += 1
                if followed > 40:
                    raise Failure('UNSAFE_PATH', 'Обнаружен цикл ссылок Node.js.')
                pending = links[current].split('/') + pending
            else:
                if pending and kind != 'directory':
                    raise Failure('UNSAFE_PATH', 'Ссылка Node.js проходит через неподходящий файл.')
                resolved.append(part)


def prepare_node():
    prefix, digest = node_archive()
    directory(NODE_ROOT, 0o755)
    release = NODE_ROOT / prefix
    current = NODE_ROOT / 'current'
    if release.is_symlink() or (release.exists() and not release.is_dir()):
        raise Failure('UNSAFE_PATH', 'Неподходящий каталог Node.js.')
    if not release.exists():
        stage = Path(tempfile.mkdtemp(prefix='.node-stage.', dir=NODE_ROOT))
        try:
            archive = stage / 'node.tar.xz'
            run(['curl', '--fail', '--silent', '--show-error', '--location', '--proto', '=https', '--proto-redir', '=https',
                 '--connect-timeout', '20', '--max-time', '240', '--max-filesize', str(100 * 1024 * 1024),
                 '--output', archive, 'https://nodejs.org/dist/v' + NODE_VERSION + '/' + prefix + '.tar.xz'],
                timeout=260, safe='Не удалось загрузить закреплённый Node.js.')
            with archive.open('rb') as stream:
                actual = hashlib.file_digest(stream, 'sha256').hexdigest()
            if actual != digest:
                raise Failure('NODE_CHECKSUM', 'Контрольная сумма Node.js не совпадает.')
            extract_node(archive, stage, prefix)
            extracted = stage / prefix
            normalize_node_tree(extracted)
            atomic(extracted / '.gitreposted-node.json', json.dumps({'version': NODE_VERSION, 'sha256': digest}), 0o644)
            os.rename(extracted, release)
            sync_directory(NODE_ROOT)
        finally:
            clean_stage(stage, NODE_ROOT, '.node-stage.')
    # A completed root-owned release is an atomic checkpoint. Never execute a
    # binary found in an app-writable path, even during --resume.
    for ancestor in (NODE_ROOT, release):
        info = ancestor.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Failure('UNSAFE_PATH', 'Node.js должен принадлежать root без чужой записи.')
    marker = read_json(release / '.gitreposted-node.json')
    if marker != {'version': NODE_VERSION, 'sha256': digest}:
        raise Failure('NODE_CHECKSUM', 'Сохранённая версия Node.js не подтверждена.')
    # Repair an interrupted installation made with the same pinned vendor
    # archive before the app UID executes Node/npm. The marker is unchanged.
    normalize_node_tree(release)
    binary = release / 'bin/node'
    for path in (release / 'bin', release / 'lib', release / 'lib/node_modules', release / 'lib/node_modules/npm',
                 release / 'lib/node_modules/npm/bin', binary, release / 'lib/node_modules/npm/bin/npm-cli.js'):
        info = path.lstat()
        if path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022 or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise Failure('UNSAFE_PATH', 'Node.js содержит неподтверждённый путь.')
    if run([binary, '--version']).strip() != ('v' + NODE_VERSION).encode():
        raise Failure('NODE_VERSION', 'Версия Node.js не соответствует release.')
    if current.is_symlink():
        if current.resolve() != release:
            raise Failure('EXISTING_RELEASE', 'Уже выбрана другая версия Node.js.')
    elif current.exists():
        raise Failure('UNSAFE_PATH', 'Путь текущего Node.js уже занят.')
    else:
        current.symlink_to(release)
        sync_directory(NODE_ROOT)


def seal_dependencies(root):
    """Seal app-created npm output using no-follow descriptors, not recursive chown."""
    def seal(descriptor):
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o755)
        for name in os.listdir(descriptor):
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                try:
                    seal(child)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
                try:
                    if not stat.S_ISREG(os.fstat(child).st_mode) or os.fstat(child).st_nlink != 1:
                        raise Failure('UNSAFE_DEPENDENCY', 'Зависимости содержат неподходящий файл.')
                    os.fchown(child, 0, 0)
                    os.fchmod(child, 0o644)
                finally:
                    os.close(child)
            else:
                raise Failure('UNSAFE_DEPENDENCY', 'Ссылки и специальные файлы зависимостей запрещены.')
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        seal(descriptor)
    finally:
        os.close(descriptor)


def prepare_dependencies(release):
    release = Path(release)
    source = release / 'src'
    validate_source(source)
    package = json.loads((source / 'package.json').read_text())
    lock_bytes = (source / 'package-lock.json').read_bytes()
    lock = json.loads(lock_bytes)
    dependencies = package.get('dependencies', {})
    if (package.get('type') != 'module' or not isinstance(dependencies, dict) or set(dependencies) != {'mysql2'}
            or not isinstance(dependencies['mysql2'], str) or lock.get('lockfileVersion') != 3
            or lock.get('packages', {}).get('', {}).get('dependencies') != dependencies):
        raise Failure('INVALID_DEPENDENCIES', 'Не подтверждён пакет зависимостей приложения.')
    checkpoint = {'lock_sha256': hashlib.sha256(lock_bytes).hexdigest(), 'node': NODE_VERSION}
    target = source / 'node_modules'
    if target.exists() or target.is_symlink():
        if target.is_symlink() or read_json(target / '.gitreposted-install.json') != checkpoint:
            raise Failure('INVALID_DEPENDENCIES', 'Существующие зависимости не подтверждены.')
        return
    stage = Path(tempfile.mkdtemp(prefix='.npm-stage.', dir=release))
    try:
        # Root creates only these fixed files before granting the new app UID
        # this isolated directory. npm never runs with root permissions.
        atomic(stage / 'package.json', (source / 'package.json').read_bytes(), 0o644)
        atomic(stage / 'package-lock.json', lock_bytes, 0o644)
        os.chown(stage, *identity(APP_USER))
        os.chmod(stage, 0o700)
        npm = NODE_ROOT / 'current/lib/node_modules/npm/bin/npm-cli.js'
        run(['runuser', '-u', APP_USER, '--', 'env', 'PATH=' + str(NODE.parent) + ':/usr/bin:/bin',
             'HOME=' + str(DATA), 'npm_config_cache=' + str(stage / '.cache'),
             NODE, npm, 'ci', '--prefix', stage, '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund'],
            timeout=600, safe='Не удалось установить закреплённые зависимости Node.js. Используйте --resume.')
        seal_dependencies(stage)
        if not (stage / 'node_modules/mysql2/promise.js').is_file():
            raise Failure('INVALID_DEPENDENCIES', 'mysql2 не прошёл проверку установки.')
        atomic(stage / 'node_modules/.gitreposted-install.json', json.dumps(checkpoint), 0o644)
        os.rename(stage / 'node_modules', target)
        sync_directory(source)
    finally:
        clean_stage(stage, release, '.npm-stage.')


def release_directory():
    # Bootstrap uses umask 077. Every traversed code ancestor needs an explicit
    # public execute bit before the separate application UID can read scripts.
    directory(APP, 0o755)
    directory(APP / 'releases', 0o755)
    release = APP / 'releases' / VERSION
    directory(release, 0o755)
    return release


def install(source, ip, host, resume=False, checked=False, package=None):
    if not checked:
        preflight(resume)
    dns_matches(host, ip)
    files = package_files(source) if package is None else package
    print('Preflight passed. Installing GitRePosted dependencies...', flush=True)
    directory(STATE, 0o700)
    save_json(STATE / 'bootstrap.json', {'installer': 'gitreposted-clean-v1', 'public_ip': ip, 'host': host})
    # The curl loader removes its temporary archive on every exit. Persist a
    # complete root-owned resume entry point before apt/network operations.
    persist_bundle(source, files)
    run(['apt-get', 'update', '-qq'], timeout=600, safe='Не удалось обновить список пакетов Ubuntu.')
    run(['apt-get', 'install', '-y', '-qq', 'nginx', 'mysql-server', 'php8.3-fpm', 'php8.3-cli',
         'php8.3-curl', 'php8.3-mbstring', 'python3-venv', 'ca-certificates', 'curl', 'logrotate'],
        timeout=1200, safe='Установка системных пакетов не завершена. Используйте --resume.')
    mysql_version = run(['mysql', '-NBe', 'SELECT VERSION()']).decode().strip()
    if not mysql_version.startswith('8.0.') or 'MariaDB' in mysql_version:
        raise Failure('MYSQL_VERSION', 'Нужен MySQL 8.0. Установка остановлена.')
    for user in (APP_USER, SETUP_USER):
        try:
            pwd.getpwnam(user)
        except KeyError:
            run(['useradd', '--system', '--user-group', '--home-dir', str(DATA if user == APP_USER else STATE), '--no-create-home', '--shell', '/usr/sbin/nologin', user])
    setup_gid = identity(SETUP_USER)[1]
    os.chown(STATE, 0, setup_gid)
    os.chmod(STATE, 0o750)
    for path in (DATA, LOG):
        directory(path, 0o750, APP_USER)
    directory(STATE / 'sessions', 0o700, SETUP_USER)
    directory(CONFIG.parent, 0o770)
    os.chown(CONFIG.parent, 0, identity(APP_USER)[1])
    release = release_directory()
    copy_tree(INSTALL / 'payload/src', release / 'src')
    prepare_node()
    prepare_dependencies(release)
    current = APP / 'current'
    if current.is_symlink():
        if current.resolve() != release:
            raise Failure('EXISTING_RELEASE', 'Найдена другая активная версия приложения.')
    elif current.exists():
        raise Failure('UNSAFE_PATH', 'Путь current уже занят.')
    else:
        current.symlink_to(release)
    certbot_venv = STATE / 'certbot'
    directory(certbot_venv, 0o700)
    if not CERTBOT.exists():
        run(['python3', '-m', 'venv', certbot_venv], timeout=120)
    run([certbot_venv / 'bin/pip', 'install', '--disable-pip-version-check', 'certbot==5.8.0'], timeout=600,
        safe='Не удалось установить Certbot 5.8.0.')
    pools()
    units()
    default = Path('/etc/nginx/sites-enabled/default')
    if default.is_symlink() and os.readlink(default) == '/etc/nginx/sites-available/default':
        default.unlink()  # Preflight guaranteed nginx did not exist before this installer.
    directory(ACME, 0o755)
    public = read_json(STATE / 'public.json', {})
    public.update({'version': VERSION, 'public_ip': ip, 'host': host, 'base_url': 'https://' + host,
                   'site_host': host, 'site_url': 'https://' + host, 'allowed_hosts': [host],
                   'tls_ready': False, 'installed': False, 'job': {'status': 'idle', 'steps': []}})
    save_json(STATE / 'public.json', public, True)
    configure_nginx(public)
    print('Obtaining trusted HTTPS certificate...', flush=True)
    obtain_certificate(host, ip)
    public['tls_ready'] = True
    configure_nginx(public)
    save_json(STATE / 'public.json', public, True)
    code = enrollment()
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', 'nginx', 'mysql', 'php8.3-fpm', 'gitreposted-installer.service',
         'gitreposted-cert-renew.timer', 'gitreposted-rate-limit-cleanup.timer'])
    show_link(host, code)


def main():
    parser = argparse.ArgumentParser(description='GitRePosted clean Ubuntu 24.04 installer')
    parser.add_argument('--public-ip')
    parser.add_argument('--host', help='Optional domain already pointing to this public IP')
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    try:
        if not args.dry_run and ((STATE / 'installed.json').exists() or (STATE / 'installed.json').is_symlink()):
            if os.geteuid() != 0:
                raise Failure('ROOT_REQUIRED', 'Запустите установщик через sudo.')
            with installer_lock():
                reconcile_installed()
                public = read_json(STATE / 'public.json', {})
                print('GitRePosted is already installed: ' + public['admin_url'])
            return
        saved = read_json(STATE / 'public.json', {}) if args.resume else {}
        if args.resume and not saved:
            saved = read_json(STATE / 'bootstrap.json', {})
        ip = public_ip(args.public_ip) if args.public_ip else public_ip(saved['public_ip']) if saved.get('public_ip') else detect_ip()
        host = host_name(args.host) if args.host else host_name(saved['host']) if saved.get('host') else ip
        preflight(args.resume)
        dns_matches(host, ip)
        if args.dry_run:
            print(json.dumps({'ok': True, 'public_ip': ip, 'host': host, 'ubuntu': '24.04', 'writes': False}))
            return
        source = Path(__file__).resolve().parents[1]
        files = package_files(source)
        if not STATE.exists():
            initialize_state(ip, host)
        with installer_lock():
            if args.resume and resume_ready():
                return
            install(source, ip, host, args.resume, checked=True, package=files)
    except Failure as error:
        print(error.code + ': ' + str(error), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
