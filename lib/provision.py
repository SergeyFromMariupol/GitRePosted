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
import re
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

VERSION = '0.1.0-rc.8'
PATH_PREFIX = '/GitRePosted'
BACKEND_PORT = 8182
INSTALL = Path('/opt/gitreposted-installer')
APP = Path('/opt/gitreposted')
STATE = Path('/var/lib/gitreposted-installer')
DATA = Path('/var/lib/gitreposted')
CONFIG = Path('/etc/gitreposted/config.json')
LOG = Path('/var/log/gitreposted')
ACME = Path('/var/www/gitreposted-acme')
SITE = Path('/etc/nginx/sites-available/gitreposted-installer')
ENABLED_SITE = Path('/etc/nginx/sites-enabled/gitreposted-installer')
RENEWAL_DIR = Path('/etc/letsencrypt/renewal')
CERTBOT = STATE / 'certbot/bin/certbot'
APP_USER = 'gitreposted'
SETUP_USER = 'gitreposted-setup'
NODE_ROOT = Path('/opt/gitreposted-node')
NODE = NODE_ROOT / 'current/bin/node'
NODE_VERSION = '24.22.1'
PACKAGE_LOCKS = (Path('/var/lib/dpkg/lock-frontend'), Path('/var/lib/dpkg/lock'))
SYSTEM_PACKAGES = ('nginx', 'mysql-server', 'php8.3-fpm', 'php8.3-cli', 'php8.3-mysql',
                   'php8.3-curl', 'php8.3-mbstring', 'python3-venv', 'ca-certificates',
                   'curl', 'cron', 'logrotate', 'unzip')
# Official release SHASUMS: https://nodejs.org/en/blog/release/v24.22.1
NODE_ARCHIVES = {
    'x86_64': ('x64', '6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6'),
    'aarch64': ('arm64', 'dbabf7a1cbf947e6059ffad2c27b80041db97dea1e553b62afdee7f13fca336e'),
}


class Failure(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class BootstrapInterrupted(BaseException):
    """CLI cancellation must bypass normal validation, retries and remapping."""
    code = 'BOOTSTRAP_INTERRUPTED'


_coinstall_spec = importlib.util.spec_from_file_location('gitreposted_coinstall', Path(__file__).with_name('coinstall.py'))
coinstall = importlib.util.module_from_spec(_coinstall_spec)
_coinstall_spec.loader.exec_module(coinstall)

_gateway_spec = importlib.util.spec_from_file_location('gitreposted_gateway', Path(__file__).with_name('gateway.py'))
gateway = importlib.util.module_from_spec(_gateway_spec)
_gateway_spec.loader.exec_module(gateway)


def path_prefix(public):
    if not isinstance(public, dict) or public.get('path_prefix', '') not in ('', PATH_PREFIX):
        raise Failure('STATE_CONFLICT', 'Некорректный путь приложения в состоянии установки.')
    prefix = public.get('path_prefix', '')
    if prefix and (type(public.get('routing_schema')) is not int or public['routing_schema'] != 1):
        raise Failure('STATE_CONFLICT', 'Не подтверждена версия общей маршрутизации.')
    return prefix


def installation_prefix(ip, resume=False):
    if resume:
        return path_prefix(read_json(STATE / 'bootstrap.json', {}))
    peer = peer_installation(ip)
    return '' if peer and not peer.get('path_prefix') else PATH_PREFIX


def gateway_call(operation, *args):
    try:
        return operation(*args)
    except gateway.GatewayError as error:
        raise Failure(error.code, str(error)) from None


@contextmanager
def shared_lock(*, create=True):
    """Serialize shared system changes with the sibling installer and broker."""
    try:
        with coinstall.shared_lock(create=create):
            yield
    except coinstall.CoInstallError as error:
        raise Failure(error.code, str(error)) from None


def peer_installation(ip=None, *, require_complete=True):
    try:
        return coinstall.inspect_peer('gitreposted', ip, require_complete=require_complete)
    except coinstall.CoInstallError as error:
        raise Failure(error.code, str(error)) from None


def ensure_hosts_available(public):
    if not isinstance(public, dict):
        raise Failure('STATE_CONFLICT', 'Некорректное состояние адресов установки.')
    hosts = [host_name(public['host']), host_name(public.get('site_host', public['host']))]
    aliases = public.get('acme_hosts', [])
    if not isinstance(aliases, list) or len(aliases) > 32:
        raise Failure('STATE_CONFLICT', 'Некорректный список доменов установки.')
    hosts.extend(host_name(host) for host in aliases)
    if public.get('pending_host'):
        hosts.append(host_name(public['pending_host']))
    try:
        return coinstall.validate_hosts('gitreposted', hosts, public.get('public_ip'), path_prefix=path_prefix(public))
    except coinstall.CoInstallError as error:
        raise Failure(error.code, str(error)) from None


def verify_passive_apache_stub():
    if shutil.which('apache2'):
        raise Failure('EXISTING_SERVICE', 'На сервере уже есть Apache. Автоматическая установка остановлена.')
    try:
        present = coinstall.passive_apache_stub()
    except coinstall.CoInstallError as error:
        raise Failure(error.code, str(error)) from None
    if present:
        owner = run(['dpkg-query', '--search', '/etc/apache2/conf-available/php8.3-fpm.conf'],
                    safe='Не удалось подтвердить происхождение неактивного PHP-FPM-файла Apache.')
        if re.fullmatch(rb'php8\.3-fpm(?::[a-z0-9-]+)?: /etc/apache2/conf-available/php8\.3-fpm\.conf\n?', owner) is None:
            raise Failure('UNMANAGED_WEB_SERVER', 'Неактивный файл Apache не принадлежит штатному пакету PHP-FPM. Установка остановлена.')


def run(argv, *, data=None, timeout=120, safe='Команда системы не выполнена.', capture=True, cwd=None):
    """Never include stdin, raw stderr or argv in raised errors."""
    child = None
    communicated = False
    try:
        child = subprocess.Popen([str(x) for x in argv], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE if capture else None, stderr=subprocess.PIPE if capture else None,
                                 start_new_session=True,
                                 cwd=cwd,
                                 env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive',
                                      'LC_ALL': 'C.UTF-8', 'NEEDRESTART_MODE': 'l'})
        try:
            output, _ = child.communicate(input=data, timeout=timeout)
            communicated = True
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
            if not communicated or child.returncode:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if child.poll() is None:
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None:
                    stream.close()
    if child.returncode:
        error = Failure('SYSTEM_COMMAND_FAILED', safe)
        error.command_returncode = child.returncode  # Safe internal classification; never argv/output.
        raise error
    return output if capture else b''


def identity(name):
    value = pwd.getpwnam(name)
    return value.pw_uid, value.pw_gid


def wait_package_locks(timeout=120):
    """Wait for the existing POSIX package locks without deleting/replacing them.

    The locks are released before dpkg starts. A new owner can win that small
    race; dpkg must still acquire its own locks and will fail safely in that case.
    """
    deadline = time.monotonic() + timeout
    while True:
        descriptors, busy = [], False
        try:
            for path in PACKAGE_LOCKS:
                try:
                    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
                except FileNotFoundError:
                    continue
                except OSError:
                    raise Failure('PACKAGE_MANAGER_UNAVAILABLE', 'Не удалось проверить блокировку пакетов. Проверьте состояние APT/dpkg и повторите --resume.') from None
                descriptors.append(fd)
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
                    raise Failure('UNSAFE_PATH', 'Обнаружен неподходящий файл блокировки пакетов; автоматическое продолжение запрещено.')
                try:
                    fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as error:
                    if error.errno not in (errno.EACCES, errno.EAGAIN):
                        raise Failure('PACKAGE_MANAGER_UNAVAILABLE', 'Не удалось проверить блокировку пакетов. Проверьте APT/dpkg и повторите --resume.') from None
                    busy = True
                    break
            if not busy:
                return
        finally:
            for fd in reversed(descriptors):
                os.close(fd)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Failure('PACKAGE_MANAGER_BUSY', 'APT/dpkg занят другой операцией. Дождитесь её завершения и повторите --resume; не удаляйте файлы блокировки.')
        time.sleep(min(1, remaining))


def prepare_system_packages(resume=False, shared_host=False):
    packages = list(SYSTEM_PACKAGES)
    if shared_host:
        # A completed sibling owns the working stack. Do not upgrade it, run
        # broad dpkg recovery, or ask apt to restart already-installed services.
        versions = shared_package_inventory()
        installed = {name.split(':', 1)[0] for name in versions}
        if not {'nginx', 'mysql-server', 'php8.3-fpm'} <= installed:
            raise Failure('SHARED_STACK_CHANGED', 'Общая установка nginx/MySQL/PHP повреждена. Восстановите первый проект до продолжения второго.')
        missing = [name for name in packages if name not in installed]
        if not missing:
            return
        add_shared_packages(missing, versions)
        return
    if resume:
        wait_package_locks()
        # A killed apt/dpkg can leave a dirty journal. apt refuses a new install
        # until dpkg merges it and finishes pending package configuration.
        try:
            run(['dpkg', '--force-confdef', '--force-confold', '--configure', '--pending'], timeout=1200,
                safe='Не удалось завершить настройку пакетов. Проверьте APT/dpkg и повторите --resume; файлы блокировки удалять нельзя.')
        except Failure as error:
            # An incomplete unpack can also leave missing dependencies. The
            # explicit install below may repair these, but may never remove
            # packages. A remaining journal/lock/configuration error still
            # causes that bounded apt command to stop safely.
            if getattr(error, 'command_returncode', None) != 1:
                raise Failure('PACKAGE_CONFIGURATION_FAILED', 'Не удалось завершить настройку пакетов. Проверьте APT/dpkg и повторите --resume; не удаляйте файлы блокировки.') from None
            repair = True
        else:
            repair = False
    else:
        repair = False
    apt = ['apt-get', '-o', 'DPkg::Lock::Timeout=120',
           '-o', 'Dpkg::Options::=--force-confdef', '-o', 'Dpkg::Options::=--force-confold']
    run(apt + ['update', '-qq'], timeout=600, safe='Не удалось обновить список пакетов Ubuntu. Проверьте сеть и APT; затем повторите --resume.')
    options = ['--fix-broken', '--no-remove'] if repair else ['--no-remove']
    run(apt + ['install', '-y', '-qq', *options, *packages],
        timeout=1200, safe='Настройка пакетов не завершена. Дождитесь других операций APT/dpkg; при необходимости выполните dpkg --configure --pending и повторите --resume. Не удаляйте файлы блокировки.')


def shared_package_inventory():
    """Read exact installed versions; a partial dpkg transaction is not adopted."""
    records = run(['dpkg-query', '--show', '--showformat=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n'])
    if len(records) > 8 * 1024 * 1024:
        raise Failure('SHARED_STACK_CHANGED', 'Не удалось проверить установленные пакеты первого проекта.')
    installed = {}
    for line in records.decode('utf-8').splitlines():
        fields = line.split('\t')
        if len(fields) != 3:
            raise Failure('SHARED_STACK_CHANGED', 'Некорректное состояние менеджера пакетов; первый проект не изменён.')
        name, version, status = fields
        if not re.fullmatch(r'[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?', name) or len(status) != 3:
            raise Failure('SHARED_STACK_CHANGED', 'Некорректное состояние менеджера пакетов; первый проект не изменён.')
        if status[1] in ('c', 'n'):
            continue
        if not re.fullmatch(r'[0-9A-Za-z.+:~_-]+', version):
            raise Failure('SHARED_STACK_CHANGED', 'Некорректная версия установленного пакета.')
        if status[1] == 'i' and status[2] == ' ' and status[0] in ('i', 'h'):
            if name in installed:
                raise Failure('SHARED_STACK_CHANGED', 'Неоднозначный список установленных пакетов.')
            installed[name] = version
        elif status[1] not in ('c', 'n'):
            raise Failure('SHARED_PACKAGE_CHANGE_REQUIRED', 'На сервере есть незавершённая настройка пакетов. Завершите её отдельно, затем повторите установку второго проекта.')
    return installed


def frozen_package_preferences(installed):
    records = []
    for name, version in sorted(installed.items()):
        if not re.fullmatch(r'[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?', name) \
                or not re.fullmatch(r'[0-9A-Za-z.+:~_-]+', version):
            raise Failure('SHARED_STACK_CHANGED', 'Невозможно закрепить версии общих пакетов.')
        records.append(f'Package: {name}\nPin: version {version}\nPin-Priority: 1001\n\n'
                       f'Package: {name}\nPin: version ?*\nPin-Priority: -1\n\n')
    return ''.join(records).encode('ascii')


@contextmanager
def shared_package_pins(installed):
    """Freeze existing packages for these commands without changing APT config."""
    if STATE.resolve() != STATE:
        raise Failure('UNSAFE_PATH', 'Небезопасный каталог состояния установщика.')
    info = STATE.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise Failure('UNSAFE_PATH', 'Каталог состояния должен принадлежать root без права посторонней записи.')
    descriptor, name = tempfile.mkstemp(prefix='.shared-apt-', dir=STATE)
    path = Path(name)
    fragments = path.with_name(path.name + '.parts')
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            os.fchown(stream.fileno(), 0, 0)
            stream.write(frozen_package_preferences(installed))
            stream.flush(); os.fsync(stream.fileno())
        fragments.mkdir(mode=0o700)
        yield ['-o', 'Dir::Etc::preferences=' + str(path),
               '-o', 'Dir::Etc::preferencesparts=' + str(fragments),
               '-o', 'APT::Get::allow-downgrades=false',
               '-o', 'APT::Get::allow-remove-essential=false',
               '-o', 'APT::Get::allow-change-held-packages=false']
    finally:
        # These exact names were created above; no shared preferences are touched.
        if fragments.exists() and not fragments.is_symlink():
            fragments.rmdir()
        path.unlink(missing_ok=True)


def validate_shared_package_plan(plan, installed):
    existing = set(installed) | {name.split(':', 1)[0] for name in installed}
    for line in plan.decode('utf-8').splitlines():
        if line.startswith(('Remv ', 'Purg ')):
            raise Failure('SHARED_PACKAGE_CHANGE_REQUIRED', 'Зависимости второго проекта требуют изменения пакетов первого. Автоматическая установка остановлена; выполните обслуживание отдельно.')
        if line.startswith(('Inst ', 'Conf ')):
            fields = line.split()
            if len(fields) < 3 or fields[1] in existing or fields[1].split(':', 1)[0] in existing or '[' in fields[2] \
                    or fields[1].split(':', 1)[0].startswith(('php', 'nginx', 'mysql', 'mariadb', 'apache2')):
                raise Failure('SHARED_PACKAGE_CHANGE_REQUIRED', 'Зависимости второго проекта требуют изменения пакетов первого. Автоматическая установка остановлена; выполните обслуживание отдельно.')


def add_shared_packages(missing, installed):
    # Installing a previously absent PHP module can itself restart FPM from
    # postinst. A completed older installation needs a separate maintenance
    # step for these; new installers prepare the same complete package set.
    protected = {'nginx', 'mysql-server', 'php8.3-fpm', 'php8.3-cli', 'php8.3-mysql',
                 'php8.3-curl', 'php8.3-mbstring'}
    if protected.intersection(missing):
        raise Failure('SHARED_PACKAGE_CHANGE_REQUIRED', 'Первой установке не хватает общих web/PHP/MySQL-пакетов. Их настройка может перезапустить службы; выполните обслуживание отдельно либо используйте оба установщика rc.6 или новее.')
    wait_package_locks()
    apt = ['apt-get', '-o', 'DPkg::Lock::Timeout=120',
           '-o', 'Dpkg::Options::=--force-confdef', '-o', 'Dpkg::Options::=--force-confold']
    run(apt + ['update', '-qq'], timeout=600, safe='Не удалось обновить список пакетов Ubuntu. Повторите --resume.')
    with shared_package_pins(installed) as pins:
        command = apt + pins + ['install', '--no-upgrade', '--no-remove', *missing]
        plan = run(command + ['--simulate'], timeout=120,
                   safe='Зависимости требуют отдельного обслуживания сервера. Пакеты первого проекта не изменены.')
        validate_shared_package_plan(plan, installed)
        if shared_package_inventory() != installed:
            raise Failure('SHARED_STACK_CHANGED', 'Список пакетов изменился во время проверки. Повторите установку после завершения других операций APT.')
        run(command + ['-y', '-qq'], timeout=1200,
            safe='Не удалось добавить зависимости второго проекта. Повторите --resume для проверки; незавершённую настройку APT/dpkg потребуется завершить отдельным обслуживанием.')


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


def preflight(resume=False, *, host=None, ip=None, explicit_host=True):
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
        if not isinstance(marker, dict) or marker.get('installer') != 'gitreposted-clean-v1' or (STATE / 'installed.json').exists():
            raise Failure('RESUME_UNAVAILABLE', 'Нет незавершённой установки для продолжения.')
        shared_host = marker.get('shared_host', False)
        prefix = path_prefix(marker)
        if type(shared_host) is not bool:
            raise Failure('STATE_CONFLICT', 'Некорректный режим совместной установки.')
        if shared_host and peer_installation(ip) is None:
            raise Failure('PEER_MISSING', 'Первый проект больше не подтверждён. Восстановите его до продолжения второго.')
        if host:
            ensure_hosts_available({'host': host, 'public_ip': ip, 'path_prefix': prefix,
                                    **({'routing_schema': 1} if prefix else {})})
        return shared_host
    for path in (INSTALL, APP, STATE, DATA, CONFIG.parent, LOG, SITE, ENABLED_SITE, NODE_ROOT):
        if path.exists() or path.is_symlink():
            raise Failure('EXISTING_INSTALLATION', 'Обнаружены существующие каталоги GitRePosted. Нужен чистый сервер.')
    for name in (APP_USER, SETUP_USER):
        try:
            pwd.getpwnam(name)
        except KeyError:
            continue
        raise Failure('EXISTING_USER', 'Системный пользователь GitRePosted уже существует.')
    peer = peer_installation(ip)
    prefix = '' if peer and not peer.get('path_prefix') else PATH_PREFIX
    if peer and not prefix and (not explicit_host or not host or host == ip):
        raise Failure('SECOND_HOST_REQUIRED', 'Для второго проекта нужен отдельный домен или поддомен. Направьте его на сервер и добавьте --host example.org.')
    if host:
        ensure_hosts_available({'host': host, 'public_ip': ip, 'path_prefix': prefix,
                                **({'routing_schema': 1} if prefix else {})})
    if peer:
        verify_passive_apache_stub()
    for service in (('mariadb',) if peer else ('nginx', 'apache2', 'mysql', 'mariadb')):
        if shutil.which(service) or Path('/etc/' + service).exists():
            raise Failure('EXISTING_SERVICE', 'На сервере уже есть web-сервер или MySQL. Автоматическая установка остановлена.')
    for port in (((3010, BACKEND_PORT) if prefix else (3010,)) if peer else (80, 443, 3010, BACKEND_PORT, 3306)):
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
    return peer is not None


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


def initialize_state(ip, host, shared_host=False, path_prefix=''):
    """Publish marker and lock together, so every visible state can resume.

    A killed process before publication may leave an unpublished private
    sibling. It is never adopted or searched for by later installations.
    """
    if path_prefix not in ('', PATH_PREFIX):
        raise Failure('STATE_CONFLICT', 'Некорректный путь новой установки.')
    if STATE.exists() or STATE.is_symlink() or not STATE.is_absolute() or STATE.parent.resolve() != STATE.parent:
        raise Failure('EXISTING_INSTALLATION', 'Каталог состояния уже существует или имеет неожиданный путь.')
    temporary = STATE.parent / ('.' + STATE.name + '-initial.' + secrets.token_hex(8))
    temporary.mkdir(mode=0o700)
    try:
        save_json(temporary / 'bootstrap.json', {'installer': 'gitreposted-clean-v1', 'public_ip': ip, 'host': host,
                                                 'shared_host': shared_host, 'path_prefix': path_prefix,
                                                 **({'routing_schema': 1} if path_prefix else {})})
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
    with shared_lock():
        public = read_json(STATE / 'public.json', {})
        if not isinstance(public, dict):
            raise Failure('STATE_CONFLICT', 'Некорректное состояние HTTPS этой установки.')
        ensure_hosts_available({**public, 'host': public.get('host', host), 'pending_host': host, 'public_ip': ip})
        if path_prefix(public):
            # Claims and the HTTP-01 route must be committed before requesting TLS.
            configure_nginx({**public, 'pending_host': host})
            authority = gateway_call(gateway.get_authority, host)
            if not authority:
                raise Failure('TLS_STATE', 'Не найден владелец сертификата общего адреса.')
            if authority['owner'] != 'gitreposted':
                if authority['tls_ready'] is not True:
                    raise Failure('TLS_OWNER_NOT_READY', 'Сначала завершите настройку HTTPS в первом установщике этого адреса.')
                return
            _obtain_certificate(host, ip, email)
            gateway_call(gateway.mark_tls_ready, 'gitreposted', host, run)
            return
        if public.get('host') and host not in [public['host'], public.get('site_host'), *public.get('acme_hosts', [])]:
            # A second named vhost cannot depend on the first site's default
            # ACME root. Broker state reserves this candidate before the call.
            configure_nginx({**public, 'pending_host': host})
        return _obtain_certificate(host, ip, email)


def _obtain_certificate(host, ip, email=''):
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


def renewal_config_exists(host):
    path = RENEWAL_DIR / (cert_name(host) + '.conf')
    if not path.exists() and not path.is_symlink():
        return False
    try:
        coinstall._parents(path.parent)
    except coinstall.CoInstallError as error:
        raise Failure(error.code, str(error)) from None
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1:
        raise Failure('UNSAFE_PATH', 'Небезопасный файл настроек продления сертификата.')
    return True


def renew_certificates():
    """Renew only this installation's certificates under the common lease."""
    if os.geteuid() != 0:
        raise Failure('ROOT_REQUIRED', 'Продление сертификатов требует root.')
    with shared_lock():
        public = read_json(STATE / 'public.json', {})
        if not isinstance(public, dict) or public.get('tls_ready') is not True:
            raise Failure('TLS_NOT_READY', 'HTTPS этой установки ещё не настроен.')
        if path_prefix(public):
            registry = gateway_call(gateway.read_registry)
            own = registry.get('projects', {}).get('gitreposted')
            immutable = ('host', 'public_ip', 'path_prefix')
            if not isinstance(own, dict) or any(own.get(key) != public.get(key) for key in immutable):
                raise Failure('TLS_STATE', 'Состояние общей маршрутизации не совпадает с адресом этой установки.')
            hosts = [host for host, authority in registry['authorities'].items()
                     if authority['owner'] == 'gitreposted' and authority['tls_ready']]
        else:
            ensure_hosts_available(public)
            hosts = list(dict.fromkeys([host_name(public['host']),
                                       host_name(public.get('site_host', public['host'])),
                                       *[host_name(host) for host in public.get('acme_hosts', [])]]))
        failed = []
        for host in hosts:
            try:
                if not renewal_config_exists(host):
                    if path_prefix(public) or host in {public['host'], public.get('site_host', public['host'])}:
                        raise Failure('TLS_STATE', 'Отсутствует настройка продления действующего HTTPS-адреса.')
                    continue  # A reserved candidate may never have passed issuance.
                run([CERTBOT, 'renew', '--quiet', '--no-random-sleep-on-renew', '--cert-name', cert_name(host),
                     '--deploy-hook', 'systemctl reload nginx'], timeout=600,
                    safe='Не удалось продлить сертификат этой установки.')
            except Failure as error:
                # One retired/broken hostname must not starve the current site.
                # Never execute Certbot for a config whose metadata was rejected.
                if error.code == 'BOOTSTRAP_INTERRUPTED':
                    raise  # Explicit CLI cancellation must stop subsequent work.
                failed.append(error.code)
        if failed:
            code = 'UNSAFE_PATH' if any(value in {'UNSAFE_PATH', 'UNTRUSTED_PEER', 'STATE_CONFLICT'} for value in failed) \
                else 'TLS_STATE' if all(value == 'TLS_STATE' for value in failed) else 'TLS_RENEW_FAILED'
            raise Failure(code, 'Не все сертификаты удалось проверить или продлить. Остальные допустимые сертификаты обработаны; проверьте настройки HTTPS, DNS и доступность HTTP.')


def backend_nginx_content(public):
    prefix = path_prefix(public)
    if not prefix:
        raise Failure('STATE_CONFLICT', 'Внутренний сайт требует постоянного пути проекта.')
    status_location = f'''location = /install/api.php {{
client_max_body_size 64k; include fastcgi_params;
fastcgi_param HTTPS on;
fastcgi_param REQUEST_URI $http_x_original_uri;
fastcgi_param SCRIPT_FILENAME {INSTALL}/web/api.php;
fastcgi_read_timeout 50s; fastcgi_pass unix:/run/php/gitreposted-installer.sock;
}}'''
    wizard = (status_location + '\nlocation = /install { return 404; }\nlocation /install/ { return 404; }'
              if public.get('installed') else f'''
location = /install {{ return 302 {prefix}/install/; }}
location = /install/ {{
include fastcgi_params; fastcgi_param HTTPS on;
fastcgi_param REQUEST_URI $http_x_original_uri;
fastcgi_param SCRIPT_FILENAME {INSTALL}/web/index.php;
fastcgi_pass unix:/run/php/gitreposted-installer.sock;
}}
{status_location}
location ^~ /install/assets/ {{ alias {INSTALL}/web/assets/; add_header X-Content-Type-Options nosniff always; }}
location /install/ {{ return 404; }}''')
    proxy = '''proxy_pass http://127.0.0.1:3010;
proxy_http_version 1.1;
proxy_set_header Host $host;
proxy_set_header X-Forwarded-Proto https;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header Connection "";
proxy_connect_timeout 5s;
proxy_read_timeout 60s;'''
    private = '''location ~ /\\. { return 404; }
location ~* \\.(?:php|py|sql|gz|ini|log|json|sh|md|pem|lock|env)(?:/|$) { return 404; }
location ~* ^/(?:src|node_modules|certs|secrets|data|runtime|storage|deployment|tools|bin|lib|scripts)(?:/|$) { return 404; }
location = /server.js { return 404; }
location = /app.js.map { return 404; }'''
    return f'''server {{
listen 127.0.0.1:{BACKEND_PORT};
server_name _;
absolute_redirect off;
port_in_redirect off;
set_real_ip_from 127.0.0.1;
real_ip_header X-Real-IP;
real_ip_recursive off;
client_max_body_size 2m;
{wizard}
location = /webhooks/telegram {{ client_max_body_size 2m; {proxy} }}
location = /webhooks/max {{ client_max_body_size 2m; {proxy} }}
{private}
location / {{ {proxy if public.get('installed') else 'return 302 ' + prefix + '/install/;'} }}
}}
'''


def nginx_content(public):
    if path_prefix(public):
        return backend_nginx_content(public)
    base_host = host_name(public['host'])
    site_host = host_name(public.get('site_host', base_host))
    installed = public.get('installed', False)
    tls_ready = public.get('tls_ready', False)
    shared_host = public.get('shared_host', False)
    if type(shared_host) is not bool:
        raise Failure('STATE_CONFLICT', 'Некорректный режим совместной установки.')
    aliases = public.get('acme_hosts', [])
    if not isinstance(aliases, list) or len(aliases) > 32:
        raise Failure('STATE_CONFLICT', 'Некорректный список доменов установки.')
    http_hosts = list(dict.fromkeys([base_host, site_host, *[host_name(host) for host in aliases]] +
                                   ([host_name(public['pending_host'])] if public.get('pending_host') else [])))
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
listen 80{'' if shared_host else ' default_server'};
server_name {' '.join(http_hosts)};
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
listen 443 ssl{' default_server' if host == base_host and not shared_host else ''};
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
    with shared_lock():
        ensure_hosts_available(public)
        if path_prefix(public):
            routed = gateway_call(gateway.configure, 'gitreposted', public, backend_nginx_content(public), run)
            public.update(routed)
            return
        return _configure_nginx(public)


def _configure_nginx(public):
    if SITE.is_symlink() or (SITE.exists() and not SITE.is_file()):
        raise Failure('UNSAFE_PATH', 'Неожиданная конфигурация nginx.')
    old = SITE.read_bytes() if SITE.exists() else None
    enabled = ENABLED_SITE
    existed = enabled.exists() or enabled.is_symlink()
    if existed and (not enabled.is_symlink() or os.readlink(enabled) != str(SITE) or enabled.lstat().st_uid != 0):
        raise Failure('UNSAFE_PATH', 'Неожиданная ссылка сайта nginx.')
    reload_attempted = False
    try:
        atomic(SITE, nginx_content(public), 0o644)
        if not existed:
            enabled.symlink_to(SITE)
        run(['nginx', '-t'], safe='Новая конфигурация nginx не прошла проверку.')
        reload_attempted = True
        run(['systemctl', 'reload', 'nginx'])
    except (Failure, OSError) as error:
        try:
            if old is not None:
                atomic(SITE, old, 0o644)
            else:
                SITE.unlink(missing_ok=True)
            if not existed and enabled.is_symlink() and os.readlink(enabled) == str(SITE):
                enabled.unlink()
            if reload_attempted:
                run(['nginx', '-t'], safe='Прежняя конфигурация nginx не прошла проверку.')
                run(['systemctl', 'reload', 'nginx'], safe='Не удалось вернуть прежнюю конфигурацию nginx.')
        except (Failure, OSError):
            raise Failure('NGINX_ROLLBACK_FAILED', 'Не удалось подтвердить возврат прежней конфигурации nginx. Проверьте nginx -t и состояние службы.') from None
        if isinstance(error, Failure):
            raise
        raise Failure('NGINX_CONFIGURATION_FAILED', 'Не удалось сохранить конфигурацию nginx; прежние настройки возвращены.') from None


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
ReadWritePaths=/etc/gitreposted /etc/nginx /var/lib/gitreposted /var/lib/gitreposted-installer -/var/lib/gitposted-suite {ACME} /var/log/gitreposted /etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt /run
[Install]
WantedBy=multi-user.target
''', 0o644)
    # Certbot is an isolated dependency of this installer, not the distribution's old version.
    atomic('/etc/systemd/system/gitreposted-cert-renew.service', f'''[Unit]
Description=Renew GitRePosted TLS certificates
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -B {INSTALL}/lib/provision.py --renew-certificates
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


def pools(shared_host=False):
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
    run(['systemctl', 'reload' if shared_host else 'restart', 'php8.3-fpm'])


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


def show_link(host, code, prefix=''):
    print('\nOpen this personal one-time link:\nhttps://' + host + prefix + '/install/#setup=' + code
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
    prefix = path_prefix(marker)
    if url.scheme != 'https' or url.netloc != host or url.path != prefix + '/control/' or url.query or url.fragment:
        raise Failure('STATE_CONFLICT', 'Некорректный адрес завершённой установки.')
    public = read_json(STATE / 'public.json', {})
    private = read_json(STATE / 'private.json', {})
    if not isinstance(public, dict) or not isinstance(private, dict):
        raise Failure('STATE_CONFLICT', 'Состояние завершённой установки недоступно.')
    if path_prefix(public) != prefix:
        raise Failure('STATE_CONFLICT', 'Путь завершённой установки не совпадает с её отметкой.')
    job = public.get('job', {})
    if not isinstance(job, dict):
        job = {}
    job = {**job, 'type': 'install', 'status': 'complete', 'error': None}
    steps = job.get('steps', [])
    job['steps'] = [{**step, 'status': 'skipped' if step.get('status') == 'skipped' else 'done'}
                    for step in steps if isinstance(step, dict)] if isinstance(steps, list) else []
    public.update({'installed': True, 'admin_url': marker['admin_url'], 'version': marker['version'],
                   'site_url': 'https://' + host + prefix, 'site_host': host, 'job': job})
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
    show_link(host_name(public['host']), code, path_prefix(public))
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
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
                try:
                    opened = os.fstat(child)
                    if not stat.S_ISREG(opened.st_mode) or opened.st_uid != 0 or opened.st_nlink != 1 or opened.st_mode & 0o022:
                        raise Failure('UNSAFE_PATH', 'Node.js содержит неподтверждённый файл.')
                    try:
                        os.fsync(child)
                    except OSError:
                        raise Failure('NODE_UNAVAILABLE', 'Запись файлов Node.js на диск не подтверждена. Проверьте диск и повторите --resume.') from None
                finally:
                    os.close(child)
                entries[current] = 'file'
            elif stat.S_ISLNK(info.st_mode):
                target = os.readlink(name, dir_fd=descriptor)
                if (info.st_uid != 0 or not target or '\\' in target or PurePosixPath(target).is_absolute()
                        or any(ord(char) < 32 or ord(char) == 127 for char in target)):
                    raise Failure('UNSAFE_PATH', 'Node.js содержит неподходящую ссылку.')
                entries[current], links[current] = 'link', target
            else:
                raise Failure('UNSAFE_PATH', 'Node.js содержит специальный файл.')
        try:
            os.fsync(descriptor)
        except OSError:
            raise Failure('NODE_UNAVAILABLE', 'Запись каталогов Node.js на диск не подтверждена. Проверьте диск и повторите --resume.') from None

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
                    try:
                        os.fsync(child)
                    except OSError:
                        raise Failure('INVALID_DEPENDENCIES', 'Запись зависимостей на диск не подтверждена. Проверьте диск и повторите --resume.') from None
                finally:
                    os.close(child)
            else:
                raise Failure('UNSAFE_DEPENDENCY', 'Ссылки и специальные файлы зависимостей запрещены.')
        try:
            os.fsync(descriptor)
        except OSError:
            raise Failure('INVALID_DEPENDENCIES', 'Запись каталогов зависимостей на диск не подтверждена. Проверьте диск и повторите --resume.') from None
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        seal(descriptor)
    finally:
        os.close(descriptor)


def verify_dependencies(source):
    """Load mysql2 as the app UID without a connection or database/provider API."""
    source = Path(source)
    target = source / 'node_modules'
    validate_source(target)
    entry = target / 'mysql2/promise.js'
    if not entry.is_file() or entry.is_symlink() or entry.stat().st_size == 0:
        raise Failure('INVALID_DEPENDENCIES', 'Сохранённые зависимости неполны. Требуется проверка установленного пакета; существующие файлы автоматически не удаляются.')
    probe = "const m=require(process.argv[1]);if(typeof m.createConnection!=='function'||typeof m.createPool!=='function')process.exit(1);"
    try:
        run(['runuser', '-u', APP_USER, '--', NODE, '-e', probe, entry], timeout=30,
            cwd=source,
            safe='Сохранённые зависимости не прошли проверку Node.js. Проверьте установленный пакет; файлы автоматически не удаляются.')
    except Failure:
        raise Failure('INVALID_DEPENDENCIES', 'Сохранённые зависимости не прошли проверку Node.js. Проверьте установленный пакет; файлы автоматически не удаляются.') from None


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
        if target.is_symlink() or not target.is_dir():
            raise Failure('INVALID_DEPENDENCIES', 'Существующие зависимости не подтверждены.')
        try:
            saved = read_json(target / '.gitreposted-install.json')
        except (OSError, ValueError, UnicodeError):
            raise Failure('INVALID_DEPENDENCIES', 'Отметка существующих зависимостей повреждена; файлы автоматически не удаляются.') from None
        if saved != checkpoint:
            raise Failure('INVALID_DEPENDENCIES', 'Существующие зависимости не подтверждены.')
        verify_dependencies(source)
        # Packages written by an older interrupted installer may have a marker
        # without durable nested file data. Re-seal/flush only this verified tree.
        seal_dependencies(target)
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
        verify_dependencies(stage)
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


def select_application_release(release, resume=False):
    """Permit cross-release recovery only before wizard/application state exists.

    This is not an updater. An interrupted early bootstrap may have selected
    an older complete runtime before ACME failed; the public loader can now
    contain a newer installer. Both release trees remain available.
    """
    release = Path(release)
    if release != APP / 'releases' / VERSION or release.is_symlink() or release.resolve() != release:
        raise Failure('UNSAFE_PATH', 'Новая версия находится вне ожидаемого каталога выпуска.')
    validate_source(release)
    current = APP / 'current'
    if current.is_symlink():
        if current.lstat().st_uid != 0:
            raise Failure('UNSAFE_PATH', 'Текущая версия приложения должна выбираться root.')
        try:
            previous = current.resolve(strict=True)
        except (OSError, RuntimeError):
            raise Failure('EXISTING_RELEASE', 'Не удалось подтвердить прежнюю версию приложения. Автоматическое переключение запрещено.') from None
        if previous == release:
            try:
                sync_directory(APP)
            except OSError:
                raise Failure('RELEASE_UNAVAILABLE', 'Запись выбора выпуска на диск не подтверждена. Проверьте диск и повторите --resume.') from None
            return
        if not resume:
            raise Failure('EXISTING_RELEASE', 'Найдена другая активная версия приложения.')
        public = read_json(STATE / 'public.json', {})
        private = read_json(STATE / 'private.json', {})
        if (not isinstance(public, dict) or not isinstance(private, dict)
                or public.get('tls_ready') or public.get('installed')
                or any(private.get(key) for key in ('settings', 'config', 'job'))
                or CONFIG.exists() or CONFIG.is_symlink()
                or (STATE / 'installed.json').exists() or (STATE / 'installed.json').is_symlink()):
            raise Failure('EXISTING_RELEASE', 'Настройка приложения уже начата. Продолжите прежний выпуск; автоматическое обновление запрещено.')
        import re
        if previous.parent != APP / 'releases' or re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?', previous.name) is None:
            raise Failure('UNSAFE_PATH', 'Прежняя версия находится вне каталога выпусков; переключение запрещено.')
        validate_source(previous)
        for name in ('server.js', 'package.json', 'package-lock.json'):
            if not (previous / 'src' / name).is_file():
                raise Failure('EXISTING_RELEASE', 'Прежний выпуск приложения не подтверждён; переключение запрещено.')
        units = run(['systemctl', 'list-units', '--all', '--type=service', '--no-legend', '--plain',
                     'gitreposted-bridge.service'], timeout=15,
                    safe='Не удалось подтвердить остановку приложения; автоматическое переключение запрещено.').decode().strip()
        if units and (len(units.splitlines()) != 1 or units.split()[:4] != ['gitreposted-bridge.service', 'loaded', 'inactive', 'dead']):
            raise Failure('EXISTING_RELEASE', 'Приложение уже запущено или запускается; автоматическое переключение запрещено.')
        temporary = APP / ('.current-select.' + secrets.token_hex(8))
        try:
            temporary.symlink_to(release)
            os.replace(temporary, current)
            sync_directory(APP)
        except OSError:
            raise Failure('RELEASE_UNAVAILABLE', 'Выбор полного выпуска на диске не подтверждён. Проверьте диск и повторите --resume; прежний каталог выпуска сохранён.') from None
        finally:
            temporary.unlink(missing_ok=True)
    elif current.exists():
        raise Failure('UNSAFE_PATH', 'Путь current уже занят.')
    else:
        try:
            current.symlink_to(release)
            sync_directory(APP)
        except OSError:
            raise Failure('RELEASE_UNAVAILABLE', 'Выбор полного выпуска на диске не подтверждён. Проверьте диск и повторите --resume.') from None


def install(source, ip, host, resume=False, checked=False, package=None):
    if not checked:
        shared_host = preflight(resume, host=host, ip=ip)
    else:
        shared_host = read_json(STATE / 'bootstrap.json', {}).get('shared_host', False)
    if type(shared_host) is not bool:
        raise Failure('STATE_CONFLICT', 'Некорректный режим совместной установки.')
    marker = read_json(STATE / 'bootstrap.json', {})
    prefix = path_prefix(marker) if marker else installation_prefix(ip, resume)
    dns_matches(host, ip)
    files = package_files(source) if package is None else package
    print('Preflight passed. Installing GitRePosted dependencies...', flush=True)
    directory(STATE, 0o700)
    save_json(STATE / 'bootstrap.json', {'installer': 'gitreposted-clean-v1', 'public_ip': ip, 'host': host,
                                         'shared_host': shared_host, 'path_prefix': prefix,
                                         **({'routing_schema': 1} if prefix else {})})
    # The curl loader removes its temporary archive on every exit. Persist a
    # complete root-owned resume entry point before apt/network operations.
    persist_bundle(source, files)
    prepare_system_packages(resume, shared_host)
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
    select_application_release(release, resume)
    certbot_venv = STATE / 'certbot'
    directory(certbot_venv, 0o700)
    if not CERTBOT.exists():
        run(['python3', '-m', 'venv', certbot_venv], timeout=120)
    run([certbot_venv / 'bin/pip', 'install', '--disable-pip-version-check', 'certbot==5.8.0'], timeout=600,
        safe='Не удалось установить Certbot 5.8.0.')
    pools(shared_host)
    units()
    default = Path('/etc/nginx/sites-enabled/default')
    if not shared_host and default.is_symlink() and os.readlink(default) == '/etc/nginx/sites-available/default':
        default.unlink()  # Preflight guaranteed nginx did not exist before this installer.
    directory(ACME, 0o755)
    public = read_json(STATE / 'public.json', {})
    public.update({'version': VERSION, 'public_ip': ip, 'host': host, 'base_url': 'https://' + host + prefix,
                   'site_host': host, 'site_url': 'https://' + host + prefix, 'allowed_hosts': [host],
                   'path_prefix': prefix, **({'routing_schema': 1} if prefix else {}),
                   'shared_host': shared_host,
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
    show_link(host, code, prefix)


@contextmanager
def interruption_signals():
    """Unwind CLI package children before releasing a shared host lease."""
    import threading
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    watched = [signal.SIGTERM]
    if hasattr(signal, 'SIGHUP'):
        watched.append(signal.SIGHUP)
    previous = {number: signal.getsignal(number) for number in watched}
    interrupted = False

    def interrupted_cli(_number, _frame):
        nonlocal interrupted
        if interrupted:
            return  # Repeated signals must not interrupt process-group cleanup.
        interrupted = True
        raise BootstrapInterrupted('Подготовка прервана. После проверки состояния пакетов продолжите установку с --resume.')

    try:
        for number in watched:
            signal.signal(number, interrupted_cli)
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def main():
    parser = argparse.ArgumentParser(description='GitRePosted clean Ubuntu 24.04 installer')
    parser.add_argument('--public-ip')
    parser.add_argument('--host', help='Optional domain already pointing to this public IP')
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--renew-certificates', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        with interruption_signals():
            if os.geteuid() != 0:
                raise Failure('ROOT_REQUIRED', 'Запустите установщик через sudo.')
            if args.renew_certificates:
                if args.host or args.public_ip or args.resume or args.dry_run:
                    raise Failure('INVALID_ARGUMENTS', 'Продление сертификатов нельзя совмещать с установкой.')
                renew_certificates()
                return
            if args.dry_run:
                # A read-only audit must not create even the common lock file.
                with shared_lock(create=False):
                    ip, host = install_target(args)
                    shared_host = preflight(args.resume, host=host, ip=ip, explicit_host=bool(args.host) or args.resume)
                    dns_matches(host, ip)
                    print(json.dumps({'ok': True, 'public_ip': ip, 'host': host, 'ubuntu': '24.04',
                                      'shared_host': shared_host, 'path_prefix': installation_prefix(ip, args.resume), 'writes': False}))
                return
            # Only the two trusted installers share this lock. It is nonblocking:
            # another bootstrap/broker job returns a safe BUSY instead of racing
            # apt, nginx or a domain claim. No lease remains while filling the UI.
            with shared_lock():
                if not args.dry_run and ((STATE / 'installed.json').exists() or (STATE / 'installed.json').is_symlink()):
                    if os.geteuid() != 0:
                        raise Failure('ROOT_REQUIRED', 'Запустите установщик через sudo.')
                    with installer_lock():
                        reconcile_installed()
                        public = read_json(STATE / 'public.json', {})
                        print('GitRePosted is already installed: ' + public['admin_url'])
                    return
                ip, host = install_target(args)
                shared_host = preflight(args.resume, host=host, ip=ip, explicit_host=bool(args.host) or args.resume)
                dns_matches(host, ip)
                source = Path(__file__).resolve().parents[1]
                files = package_files(source)
                if not STATE.exists():
                    initialize_state(ip, host, shared_host is True, installation_prefix(ip))
                with installer_lock():
                    if args.resume and resume_ready():
                        return
                    install(source, ip, host, args.resume, checked=True, package=files)
    except (Failure, BootstrapInterrupted) as error:
        print(error.code + ': ' + str(error), file=sys.stderr)
        sys.exit(1)


def install_target(args):
    saved = read_json(STATE / 'public.json', {}) if args.resume else {}
    if args.resume and not saved:
        saved = read_json(STATE / 'bootstrap.json', {})
    ip = public_ip(args.public_ip) if args.public_ip else public_ip(saved['public_ip']) if saved.get('public_ip') else detect_ip()
    inherited = None
    if not args.resume and not args.host:
        peer = peer_installation(ip)
        if peer and peer.get('path_prefix'):
            inherited = peer.get('site_host') or peer.get('host')
    host = host_name(args.host) if args.host else host_name(saved['host']) if saved.get('host') else host_name(inherited) if inherited else ip
    return ip, host


if __name__ == '__main__':
    main()
