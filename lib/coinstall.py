"""Trust and serialize the two installers without adopting arbitrary host services.

This file is identical in both distributions. It reads only fixed root-owned
installer metadata; application credentials are never opened or executed.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import stat
import threading
from urllib.parse import urlsplit

ROOT = Path('/')
PROJECTS = ('gitposted', 'gitreposted')
_held = threading.local()


class CoInstallError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _fail(code='UNTRUSTED_PEER', message='Соседняя установка не прошла проверку. Существующие сайты и базы не изменены.'):
    raise CoInstallError(code, message)


def _path(value):
    return ROOT / value.lstrip('/')


def _project(project):
    if project not in PROJECTS:
        _fail()
    return PROJECTS[1] if project == PROJECTS[0] else PROJECTS[0]


def _host(value):
    if not isinstance(value, str) or value != value.strip() or len(value) > 253:
        _fail()
    value = value.lower()
    try:
        address = ipaddress.ip_address(value)
        if address.version == 4 and address.is_global:
            return str(address)
        _fail()
    except ValueError:
        pass
    labels = value.split('.')
    if len(labels) < 2 or labels[-1].isdigit() or value.endswith(('.local', '.localhost', '.invalid', '.test')) \
            or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels):
        _fail()
    return value


def _parents(path, *, allow_writable_leaf=False):
    """Every root-owned ancestor must exclude group/other mutation."""
    if not path.is_absolute() or ROOT not in (path, *path.parents):
        _fail()
    for item in (path, *path.parents):
        info = item.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != 0 \
                or (info.st_mode & 0o022 and not (allow_writable_leaf and item == path and not info.st_mode & 0o002)):
            _fail()
        if item == ROOT:
            break


def _regular(path, *, owner=0, private=False, app_config=False, limit=1024 * 1024):
    _parents(path.parent, allow_writable_leaf=app_config)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        forbidden = 0o077 if private or app_config else 0o022
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & forbidden \
                or info.st_nlink != 1 or info.st_size > limit:
            _fail()
        if app_config:
            return b''  # Only metadata; never read a sibling's credentials.
        value = os.read(descriptor, limit + 1)
        if len(value) != info.st_size or len(value) > limit:
            _fail()
        return value
    finally:
        os.close(descriptor)


def _json(path, *, private=False):
    try:
        value = json.loads(_regular(path, private=private).decode('utf-8'))
    except (ValueError, UnicodeError):
        _fail()
    if not isinstance(value, dict):
        _fail()
    return value


def _optional_json(path, *, private=False):
    if path.exists() or path.is_symlink():
        return _json(path, private=private)
    return None


def _nginx_main():
    """Allow stock includes and tuning, never additional inline/hidden sites."""
    content = _regular(_path('/etc/nginx/nginx.conf')).decode('utf-8')
    tokens, value, quote, escaped, comment = [], '', None, False, False
    for char in content:
        if comment:
            if char == '\n':
                comment = False
            continue
        if escaped:
            value += char
            escaped = False
            continue
        if char == '\\':
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            else:
                value += char
            continue
        if char in ('"', "'"):
            quote = char
        elif char == '#':
            if value:
                tokens.append(value)
                value = ''
            comment = True
        elif char.isspace() or char in '{};':
            if value:
                tokens.append(value)
                value = ''
            if char in '{};':
                tokens.append(char)
        else:
            value += char
    if quote or escaped:
        _fail('UNMANAGED_WEB_SERVER', 'Не удалось проверить основную конфигурацию nginx.')
    if value:
        tokens.append(value)
    permitted = {'/etc/nginx/modules-enabled/*.conf', '/etc/nginx/mime.types',
                 '/etc/nginx/conf.d/*.conf', '/etc/nginx/sites-enabled/*'}
    includes = set()
    for index, token in enumerate(tokens):
        if index and tokens[index - 1] not in ('{', '}', ';'):
            continue
        if token == 'server' and tokens[index + 1:index + 2] == ['{']:
            _fail('UNMANAGED_WEB_SERVER', 'В основной конфигурации nginx найдены другие серверы. Совместная установка остановлена.')
        if token == 'include':
            if index + 2 >= len(tokens) or tokens[index + 2] != ';' or tokens[index + 1] not in permitted:
                _fail('UNMANAGED_WEB_SERVER', 'В nginx подключена дополнительная конфигурация. Совместная установка остановлена.')
            includes.add(tokens[index + 1])
    if '/etc/nginx/sites-enabled/*' not in includes:
        _fail('UNMANAGED_WEB_SERVER', 'nginx не использует стандартный каталог сайтов. Совместная установка остановлена.')


def passive_apache_stub():
    """PHP-FPM ships one inactive Apache fragment even without Apache itself.

    Inspect exactly these three paths. Nothing resembling a real Apache site,
    additional fragment or active configuration is adopted by the installer.
    The caller separately verifies the absence of a binary and dpkg ownership.
    """
    base = _path('/etc/apache2')
    try:
        if not base.exists() and not base.is_symlink():
            return False
        _parents(base)
        if {path.name for path in base.iterdir()} != {'conf-available'}:
            _fail()
        fragments = base / 'conf-available'
        _parents(fragments)
        if {path.name for path in fragments.iterdir()} != {'php8.3-fpm.conf'}:
            _fail()
        _regular(fragments / 'php8.3-fpm.conf')
        return True
    except (CoInstallError, OSError):
        _fail('UNMANAGED_WEB_SERVER', 'Обнаружена конфигурация Apache за пределами штатного неактивного PHP-FPM-файла. Совместная установка остановлена.')


def _managed_sites(project, peer):
    _nginx_main()
    enabled = _path('/etc/nginx/sites-enabled')
    _parents(enabled)
    seen = set()
    for item in enabled.iterdir():
        if item.name not in {project + '-installer', peer + '-installer'}:
            _fail('UNMANAGED_WEB_SERVER', 'Обнаружены другие сайты nginx. Автоматическая совместная установка остановлена.')
        info = item.lstat()
        if not stat.S_ISLNK(info.st_mode) or info.st_uid != 0 \
                or os.readlink(item) != '/etc/nginx/sites-available/' + item.name:
            _fail()
        _regular(_path('/etc/nginx/sites-available/' + item.name))
        seen.add(item.name)
    if peer + '-installer' not in seen:
        _fail()
    conf = _path('/etc/nginx/conf.d')
    if conf.exists() or conf.is_symlink():
        _parents(conf)
        if any(conf.iterdir()):
            _fail('UNMANAGED_WEB_SERVER', 'Обнаружена дополнительная конфигурация nginx. Автоматическая установка остановлена.')


def inspect_peer(project, ip=None, *, require_complete=True):
    """Return a verified peer or None; partial metadata only reserves hosts.

    A partial peer can never authorize adoption of nginx/MySQL. Operations on
    an already installed application may still inspect its root-owned claims.
    """
    peer = _project(project)
    state = _path('/var/lib/' + peer + '-installer')
    try:
        if not state.exists() and not state.is_symlink():
            remnants = ('/opt/' + peer + '-installer', '/opt/' + peer,
                        '/etc/nginx/sites-available/' + peer + '-installer', '/etc/' + peer)
            if any(_path(name).exists() or _path(name).is_symlink() for name in remnants):
                _fail()
            return None
        _parents(state)
        bootstrap = _json(state / 'bootstrap.json', private=True)
        if bootstrap.get('installer') != peer + '-clean-v1':
            _fail()
        if type(bootstrap.get('shared_host', False)) is not bool:
            _fail()
        peer_ip = _host(bootstrap.get('public_ip'))
        if not ipaddress.ip_address(peer_ip).is_global or (ip is not None and peer_ip != ip):
            _fail('PEER_ADDRESS_MISMATCH', 'Соседний проект настроен на другой публичный IP. Проверьте адрес сервера.')
        hosts = {_host(bootstrap.get('host'))}
        public = _optional_json(state / 'public.json')
        if public is not None:
            if public.get('public_ip') != peer_ip:
                _fail()
            hosts.add(_host(public.get('host')))
            hosts.add(_host(public.get('site_host', public.get('host'))))
            aliases = public.get('acme_hosts', [])
            if not isinstance(aliases, list) or len(aliases) > 32:
                _fail()
            hosts.update(_host(alias) for alias in aliases)
            for key in ('pending_host',):
                if public.get(key):
                    hosts.add(_host(public[key]))
        private = _optional_json(state / 'private.json', private=True)
        if private and private.get('host_settings'):
            pending = private['host_settings']
            if not isinstance(pending, dict):
                _fail()
            hosts.add(_host(pending.get('host')))
        marker = _optional_json(state / 'installed.json', private=True)
        complete = marker is not None
        if not complete:
            if require_complete:
                _fail('PEER_INCOMPLETE', 'Сначала завершите установку другого проекта, затем повторите эту команду.')
            return {'project': peer, 'hosts': sorted(hosts), 'public_ip': peer_ip, 'complete': False,
                    'shared_host': bool(bootstrap.get('shared_host', False)), 'site_url': None, 'version': None}
        if not public or public.get('installed') is not True or public.get('tls_ready') is not True \
                or type(marker.get('installed_at')) is not int or marker['installed_at'] <= 0 \
                or not isinstance(marker.get('version'), str) or not 1 <= len(marker['version']) <= 100:
            _fail()
        url = urlsplit(marker.get('admin_url', ''))
        if url.scheme != 'https' or url.netloc != _host(public.get('site_host')) \
                or url.path != '/control/' or url.query or url.fragment \
                or public.get('site_url') != 'https://' + url.netloc:
            _fail()
        app_identity = pwd.getpwnam(peer)
        _regular(_path('/etc/' + peer + ('/config.php' if peer == 'gitposted' else '/config.json')),
                 owner=app_identity.pw_uid, app_config=True)
        site = _path('/etc/nginx/sites-available/' + peer + '-installer')
        content = _regular(site).decode('utf-8')
        site_names = {name for names in re.findall(r'\bserver_name\s+([^;]+);', content) for name in names.split() if name != '_'}
        if not {_host(public['host']), _host(public['site_host'])}.issubset(site_names):
            _fail()
        hosts.update(_host(name) for name in site_names)
        _managed_sites(project, peer)
        return {'project': peer, 'hosts': sorted(hosts), 'public_ip': peer_ip, 'complete': True,
                'shared_host': bool(bootstrap.get('shared_host', False)), 'site_url': public['site_url'], 'version': marker['version']}
    except CoInstallError:
        raise
    except (OSError, ValueError, KeyError, TypeError, UnicodeError):
        _fail()


def validate_hosts(project, hosts, ip=None):
    candidate = {_host(value) for value in hosts if value}
    if not candidate:
        _fail()
    peer = inspect_peer(project, ip, require_complete=False)
    if peer and candidate.intersection(peer['hosts']):
        _fail('HOST_IN_USE', 'Этот адрес уже используется другим проектом. Укажите отдельный домен или поддомен через --host.')
    return peer


@contextmanager
def shared_lock(*, create=True):
    """Nonblocking across processes/threads; nesting in the same thread is safe."""
    if getattr(_held, 'depth', 0):
        _held.depth += 1
        try:
            yield
        finally:
            _held.depth -= 1
        return
    descriptor = None
    try:
        try:
            path = _path('/run/gitposted-suite.lock')
            _parents(path.parent)
            missing = not create and not path.exists() and not path.is_symlink()
            if not missing:
                flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_CREAT if create else 0)
                descriptor = os.open(path, flags, 0o600)
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_nlink != 1:
                    _fail('UNSAFE_PATH', 'Небезопасная общая блокировка установщиков.')
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    _fail('SHARED_INSTALL_BUSY', 'Другой установщик занят. Дождитесь завершения его текущего шага и повторите действие.')
        except OSError:
            _fail('SHARED_LOCK_UNAVAILABLE', 'Не удалось получить общую блокировку установщиков.')
        if missing:
            yield  # Read-only preflight does not create any persistent state.
            return
        _held.depth = 1
        try:
            yield
        finally:
            _held.depth = 0
    finally:
        if descriptor is not None:
            os.close(descriptor)
