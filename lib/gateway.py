"""Root-owned routing for the two prefixed installers.

Callers hold the suite lease. No application config, credentials, providers or
system services other than nginx validation/reload are accessed here.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat

ROOT = Path('/')
PREFIXES = {'gitposted': '/GitPosted', 'gitreposted': '/GitRePosted'}
PORTS = {'gitposted': 8181, 'gitreposted': 8182}
REGISTRY = '/var/lib/gitposted-suite/routes.json'
SITE = '/etc/nginx/sites-available/gitposted-suite'
ENABLED = '/etc/nginx/sites-enabled/gitposted-suite'
_GATEWAY_MARKER = '# GitPosted suite gateway; routing schema 1\n'
_PUBLIC_KEYS = {'host', 'site_host', 'public_ip', 'path_prefix', 'tls_ready',
                'installed', 'acme_hosts', 'pending_host'}


class GatewayError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _fail(code='GATEWAY_STATE_INVALID', message='Не удалось проверить общую маршрутизацию проектов. Существующие настройки сохранены.'):
    raise GatewayError(code, message)


def _path(value):
    return ROOT / value.lstrip('/')


def _project(project):
    if project not in PREFIXES:
        _fail('INVALID_PROJECT', 'Неизвестный проект маршрутизации.')
    return project


def _host(value):
    if not isinstance(value, str) or value != value.strip() or not 1 <= len(value) <= 253:
        _fail('INVALID_HOST', 'Некорректный адрес проекта.')
    value = value.lower()
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        labels = value.split('.')
        if len(labels) < 2 or labels[-1].isdigit() or value.endswith(('.local', '.localhost', '.invalid', '.test')) \
                or any(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) is None for label in labels):
            _fail('INVALID_HOST', 'Нужен публичный IPv4 или корректный домен без пути и порта.')
        return value
    if address.version != 4 or not address.is_global:
        _fail('INVALID_HOST', 'Нужен публичный IPv4 сервера.')
    return str(address)


def _certificate(owner, host):
    return owner + '-' + hashlib.sha256(host.encode('ascii')).hexdigest()[:12]


def _authority(owner, host):
    return {'owner': owner, 'cert_name': _certificate(owner, host),
            'acme_root': '/var/www/' + owner + '-acme', 'tls_ready': False}


def _descriptor(project, public):
    _project(project)
    if not isinstance(public, dict) or public.get('path_prefix') != PREFIXES[project]:
        _fail('INVALID_PREFIX', 'Для проекта требуется его постоянный адрес /GitPosted или /GitRePosted.')
    host = _host(public.get('host'))
    site_host = _host(public.get('site_host', host))
    ip = _host(public.get('public_ip'))
    try:
        if ipaddress.ip_address(ip).version != 4:
            raise ValueError()
    except ValueError:
        _fail('INVALID_HOST', 'Не указан публичный IPv4 сервера.')
    for candidate in (host, site_host):
        try:
            if ipaddress.ip_address(candidate) != ipaddress.ip_address(ip):
                _fail('GATEWAY_ADDRESS_MISMATCH', 'IP проекта отличается от публичного IP сервера.')
        except ValueError:
            pass
    if type(public.get('tls_ready', False)) is not bool or type(public.get('installed', False)) is not bool:
        _fail()
    aliases = public.get('acme_hosts', [])
    if not isinstance(aliases, list) or len(aliases) > 32:
        _fail('INVALID_HOST', 'Некорректный список адресов сертификатов.')
    aliases = list(dict.fromkeys(_host(value) for value in aliases))
    result = {'host': host, 'site_host': site_host, 'public_ip': ip,
              'path_prefix': PREFIXES[project], 'tls_ready': public.get('tls_ready', False),
              'installed': public.get('installed', False), 'acme_hosts': aliases}
    if public.get('pending_host'):
        result['pending_host'] = _host(public['pending_host'])
    for candidate in [*aliases, *([result['pending_host']] if 'pending_host' in result else [])]:
        try:
            if ipaddress.ip_address(candidate) != ipaddress.ip_address(ip):
                _fail('GATEWAY_ADDRESS_MISMATCH', 'IP проекта отличается от публичного IP сервера.')
        except ValueError:
            pass
    return result


def project_public(project, public):
    """Return validated route fields and their public URLs, without secrets."""
    result = _descriptor(project, public)
    prefix = PREFIXES[project]
    result.update(base_url='https://' + result['host'] + prefix,
                  site_url='https://' + result['site_host'] + prefix,
                  admin_url='https://' + result['site_host'] + prefix + '/control/',
                  install_url='https://' + result['host'] + prefix + '/install/')
    return result


def _hosts(public):
    return list(dict.fromkeys([public['host'], public['site_host'], *public['acme_hosts'],
                              *([public['pending_host']] if public.get('pending_host') else [])]))


def _empty():
    return {'version': 1, 'projects': {}, 'authorities': {}, 'default_host': None}


def _validate_registry(value):
    if not isinstance(value, dict) or set(value) != {'version', 'projects', 'authorities', 'default_host'} \
            or type(value['version']) is not int or value['version'] != 1 \
            or not isinstance(value['projects'], dict) or not isinstance(value['authorities'], dict) \
            or len(value['projects']) > len(PREFIXES) or len(value['authorities']) > 256:
        _fail()
    projects = value['projects']
    for name, public in projects.items():
        if not isinstance(public, dict) or set(public) - _PUBLIC_KEYS or _descriptor(name, public) != public:
            _fail()
    addresses = {public['public_ip'] for public in projects.values()}
    if len(addresses) > 1:
        _fail('GATEWAY_ADDRESS_MISMATCH', 'Проекты настроены на разные IP сервера.')
    authorities = value['authorities']
    for host, authority in authorities.items():
        if _host(host) != host or not isinstance(authority, dict) \
                or set(authority) != {'owner', 'cert_name', 'acme_root', 'tls_ready'} \
                or authority.get('owner') not in projects or type(authority.get('tls_ready')) is not bool:
            _fail()
        expected = _authority(authority['owner'], host)
        if any(authority.get(key) != expected[key] for key in ('owner', 'cert_name', 'acme_root')):
            _fail()
    if any(host not in authorities for public in projects.values() for host in _hosts(public)):
        _fail()
    if (not authorities and value['default_host'] is not None) or (authorities and value['default_host'] not in authorities):
        _fail()
    if bool(projects) != bool(authorities):
        _fail()
    return copy.deepcopy(value)


def _parents(path):
    """Check only ancestors inside ROOT, which is injectable for fixtures."""
    base = Path(ROOT)
    if not path.is_absolute() or path != base and base not in path.parents:
        _fail('UNSAFE_PATH', 'Путь общей маршрутизации выходит за разрешённый каталог.')
    current = path
    while True:
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            _fail('UNSAFE_PATH', 'Каталог общей маршрутизации должен принадлежать root и быть защищён от записи.')
        if current == base:
            break
        current = current.parent


def _read(path, *, private=False, limit=1048576):
    _parents(path.parent)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 \
            or info.st_mode & (0o077 if private else 0o022) or info.st_size > limit:
        _fail('UNSAFE_PATH', 'Небезопасный файл общей маршрутизации.')
    return path.read_bytes()


def read_registry():
    path = _path(REGISTRY)
    try:
        if not path.exists() and not path.is_symlink():
            # Even an absent file must not hide a symlinked existing ancestor.
            current = path.parent
            while not current.exists() and not current.is_symlink() and current != Path(ROOT):
                current = current.parent
            _parents(current)
            return _empty()
        return _validate_registry(json.loads(_read(path, private=True, limit=262144)))
    except GatewayError:
        raise
    except (OSError, ValueError, TypeError, UnicodeError):
        _fail()


def get_authority(host):
    return copy.deepcopy(read_registry()['authorities'].get(_host(host)))


def _tokens(content):
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
                tokens.append(value); value = ''
            comment = True
        elif char.isspace() or char in '{};':
            if value:
                tokens.append(value); value = ''
            if char in '{};':
                tokens.append(char)
        else:
            value += char
    if quote or escaped:
        _fail('INVALID_BACKEND', 'Не удалось проверить внутреннюю конфигурацию nginx.')
    if value:
        tokens.append(value)
    return tokens


def _backend_marker(project):
    return '# GitPosted suite backend: ' + project + '; routing schema 1\n'


def _backend(project, content):
    if not isinstance(content, str) or '\0' in content or len(content.encode('utf-8')) > 1048576:
        _fail('INVALID_BACKEND', 'Некорректная внутренняя конфигурация проекта.')
    tokens = _tokens(content)
    listens = []
    servers = 0
    for index, token in enumerate(tokens):
        if index and tokens[index - 1] not in ('{', '}', ';'):
            continue
        if token == 'server' and tokens[index + 1:index + 2] == ['{']:
            servers += 1
        if token == 'listen':
            end = index + 1
            while end < len(tokens) and tokens[end] != ';':
                end += 1
            listens.append(tokens[index + 1:end])
        if token == 'include':
            if tokens[index + 1:index + 3] not in (['fastcgi_params', ';'], ['/etc/nginx/fastcgi_params', ';']):
                _fail('INVALID_BACKEND', 'Внутренний nginx содержит дополнительную конфигурацию.')
    expected = ['127.0.0.1:' + str(PORTS[project])]
    if servers != 1 or listens not in ([expected], [expected + ['default_server']]):
        _fail('INVALID_BACKEND', 'Проект должен слушать только свой внутренний порт nginx.')
    return _backend_marker(project) + content.removeprefix(_backend_marker(project))


def _strict_host(host):
    return 'if ($http_host = "") { return 444; }\nif ($host != ' + host + ') { return 444; }'


def _selector(projects):
    labels = {'gitposted': 'GitPosted', 'gitreposted': 'GitRePosted'}
    links = ''.join('<li><a href="' + PREFIXES[name] + '/">' + labels[name] + '</a></li>' for name in sorted(projects))
    return '<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GitPosted · GitRePosted</title><h1>Ваши проекты</h1><ul>' + links + '</ul></html>'


def render_registry(registry):
    registry = _validate_registry(registry)
    if not registry['authorities']:
        return _GATEWAY_MARKER
    ready = sorted(host for host, value in registry['authorities'].items() if value['tls_ready'])
    tls_default = registry['default_host'] if registry['default_host'] in ready else ready[0] if ready else None
    blocks = [_GATEWAY_MARKER]
    for host, authority in sorted(registry['authorities'].items()):
        projects = [name for name, public in registry['projects'].items() if host in _hosts(public)]
        acme = 'location ^~ /.well-known/acme-challenge/ { root ' + authority['acme_root'] + '; default_type text/plain; try_files $uri =404; }'
        http_body = 'return 308 https://' + host + '$request_uri;' if authority['tls_ready'] else 'default_type text/plain; return 503 "HTTPS is being configured. Return to the SSH console.\\n";'
        blocks.append('server {\nlisten 80' + (' default_server' if host == registry['default_host'] else '') + ';\nserver_name ' + host + ';\n' + _strict_host(host) + '\n' + acme + '\nlocation / { ' + http_body + ' }\n}\n')
        if not authority['tls_ready']:
            continue
        locations = []
        for project in sorted(projects):
            public = registry['projects'][project]
            prefix = PREFIXES[project]
            canonical = public['site_host']
            if public['installed'] and host != canonical:
                locations.append('location = ' + prefix + ' { return 308 https://' + canonical + prefix + '/$is_args$args; }\nlocation ^~ ' + prefix + '/ { return 308 https://' + canonical + '$request_uri; }')
                continue
            locations.append('location = ' + prefix + ' { return 308 https://' + host + prefix + '/$is_args$args; }\nlocation ^~ ' + prefix + '/ {\n' +
                             'proxy_pass http://127.0.0.1:' + str(PORTS[project]) + '/;\nproxy_http_version 1.1;\nproxy_set_header Connection "";\n' +
                             'proxy_set_header Host ' + host + ';\nproxy_set_header X-Forwarded-Host ' + host + ';\nproxy_set_header X-Forwarded-Proto https;\n' +
                             'proxy_set_header X-Forwarded-Prefix ' + prefix + ';\nproxy_set_header X-Real-IP $remote_addr;\nproxy_set_header X-Forwarded-For $remote_addr;\n' +
                             'proxy_set_header X-Original-URI $request_uri;\nproxy_redirect off;\nproxy_connect_timeout 10s;\nproxy_read_timeout 1300s;\n}\n')
        locations.append('location = / { default_type text/html; return 200 \'' + _selector(projects) + '\'; }')
        locations.append('location / { return 404; }')
        cert = '/etc/letsencrypt/live/' + authority['cert_name']
        blocks.append('server {\nlisten 443 ssl' + (' default_server' if host == tls_default else '') + ';\nserver_name ' + host + ';\n' + _strict_host(host) + '\n' +
                      'ssl_certificate ' + cert + '/fullchain.pem;\nssl_certificate_key ' + cert + '/privkey.pem;\nssl_protocols TLSv1.2 TLSv1.3;\n' +
                      'client_max_body_size 2m;\nadd_header X-Content-Type-Options nosniff always;\n' + '\n'.join(locations) + '\n}\n')
    return '\n'.join(blocks)


def _directory(path, mode=0o755):
    if not path.exists() and not path.is_symlink():
        _directory(path.parent)
        path.mkdir(mode=mode)
        path.chmod(mode)
    _parents(path)
    if mode == 0o700 and path.lstat().st_mode & 0o077:
        _fail('UNSAFE_PATH', 'Каталог состояния общей маршрутизации должен иметь режим 0700.')


def _fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic(path, content, mode):
    _parents(path.parent)
    temporary = path.with_name('.' + path.name + '.' + secrets.token_hex(8) + '.tmp')
    descriptor = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, 'wb') as stream:
            descriptor = None
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


def _snapshot_file(path, *, private=False, marker=None):
    if not path.exists() and not path.is_symlink():
        _parents(path.parent)
        return None
    value = _read(path, private=private)
    if marker is not None and not value.startswith(marker.encode('utf-8')):
        _fail('UNMANAGED_WEB_SERVER', 'Файл nginx не принадлежит общей маршрутизации. Автоматическая замена остановлена.')
    return value, stat.S_IMODE(path.lstat().st_mode)


def _snapshot_link(path, target):
    _parents(path.parent)
    if not path.exists() and not path.is_symlink():
        return False
    info = path.lstat()
    if not stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or os.readlink(path) != target:
        _fail('UNSAFE_PATH', 'Неожиданная ссылка общей конфигурации nginx.')
    return True


def _transaction(registry, run_callback, backend_updates=None):
    if getattr(os, 'geteuid', lambda: -1)() != 0:
        _fail('ROOT_REQUIRED', 'Общая маршрутизация настраивается только от root.')
    registry = _validate_registry(registry)
    backend_updates = backend_updates or {}
    _directory(_path('/etc/nginx/sites-available'))
    _directory(_path('/etc/nginx/sites-enabled'))
    _directory(_path('/var/lib/gitposted-suite'), 0o700)
    files = {
        _path(REGISTRY): (json.dumps(registry, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('utf-8') + b'\n', 0o600, True, None),
        _path(SITE): (render_registry(registry).encode('utf-8'), 0o644, False, _GATEWAY_MARKER),
    }
    links = {_path(ENABLED): SITE}
    for project in registry['projects']:
        relative = '/etc/nginx/sites-available/' + project + '-installer'
        path = _path(relative)
        links[_path('/etc/nginx/sites-enabled/' + project + '-installer')] = relative
        if project in backend_updates:
            files[path] = (_backend(project, backend_updates[project]).encode('utf-8'), 0o644, False, _backend_marker(project))
        else:
            value = _snapshot_file(path, marker=_backend_marker(project))
            if value is None:
                _fail('GATEWAY_BACKEND_MISSING', 'Отсутствует внутренняя конфигурация установленного проекта.')
            _backend(project, value[0].decode('utf-8'))
    snapshots = {path: _snapshot_file(path, private=value[2], marker=value[3]) for path, value in files.items()}
    link_snapshots = {path: _snapshot_link(path, target) for path, target in links.items()}
    reloaded = False
    try:
        # Backend/gateway files precede the durable registry commit. An
        # interrupted operation is reconstructed from the same validated claims.
        for path, value in sorted(files.items(), key=lambda item: item[0] == _path(REGISTRY)):
            _atomic(path, value[0], value[1])
        for path, target in links.items():
            if not link_snapshots[path]:
                path.symlink_to(target)
                _fsync_directory(path.parent)
        run_callback(['nginx', '-t'], safe='Общая конфигурация nginx не прошла проверку.')
        reloaded = True
        run_callback(['systemctl', 'reload', 'nginx'], safe='Не удалось применить общую маршрутизацию nginx.')
    except BaseException:
        rollback_failed = False
        for path, snapshot in snapshots.items():
            try:
                if snapshot is None:
                    path.unlink(missing_ok=True)
                    _fsync_directory(path.parent)
                else:
                    _atomic(path, snapshot[0], snapshot[1])
            except (OSError, GatewayError):
                rollback_failed = True
        for path, existed in link_snapshots.items():
            try:
                if not existed:
                    if path.is_symlink() and os.readlink(path) == links[path]:
                        path.unlink()
                        _fsync_directory(path.parent)
                    elif path.exists() or path.is_symlink():
                        rollback_failed = True
            except OSError:
                rollback_failed = True
        if reloaded and not rollback_failed:
            try:
                run_callback(['systemctl', 'reload', 'nginx'], safe='Не удалось подтвердить возврат прежней маршрутизации nginx.')
            except BaseException:
                rollback_failed = True
        if rollback_failed:
            _fail('GATEWAY_ROLLBACK_FAILED', 'Возврат прежней маршрутизации не подтверждён. Остановите установку и проверьте nginx через SSH.')
        raise


def configure(project, public, backend_content, run_callback):
    """Register/reconfigure one project. Caller holds the common suite lease."""
    try:
        descriptor = _descriptor(project, public)
        registry = read_registry()
        other_ips = {value['public_ip'] for name, value in registry['projects'].items() if name != project}
        if other_ips and other_ips != {descriptor['public_ip']}:
            _fail('GATEWAY_ADDRESS_MISMATCH', 'Проекты настроены на разные IP сервера.')
        registry['projects'][project] = descriptor
        for host in _hosts(descriptor):
            registry['authorities'].setdefault(host, _authority(project, host))
            if registry['default_host'] is None:
                registry['default_host'] = host
        descriptor['tls_ready'] = registry['authorities'][descriptor['site_host']]['tls_ready']
        _transaction(registry, run_callback, {project: backend_content})
        return project_public(project, descriptor)
    except GatewayError:
        raise
    except (OSError, ValueError, TypeError, UnicodeError):
        _fail('GATEWAY_CONFIG_FAILED', 'Не удалось сохранить общую маршрутизацию. Проверьте права и свободное место через SSH.')


def mark_tls_ready(project, host, run_callback):
    """Publish an issued certificate; only its original owner may do so."""
    try:
        _project(project)
        host = _host(host)
        registry = read_registry()
        authority = registry['authorities'].get(host)
        if not authority or authority['owner'] != project:
            _fail('CERTIFICATE_OWNER_REQUIRED', 'Этот HTTPS-адрес обслуживается другим установщиком.')
        authority['tls_ready'] = True
        for public in registry['projects'].values():
            public['tls_ready'] = registry['authorities'][public['site_host']]['tls_ready']
        _transaction(registry, run_callback)
        return copy.deepcopy(authority)
    except GatewayError:
        raise
    except (OSError, ValueError, TypeError, UnicodeError):
        _fail('GATEWAY_CONFIG_FAILED', 'Не удалось подключить HTTPS общей маршрутизации. Проверьте nginx через SSH.')
