<?php

declare(strict_types=1);

namespace GitRePostedInstaller;

final class WizardError extends \RuntimeException
{
    public function __construct(public readonly string $errorCode, string $message, public readonly int $status = 400)
    {
        parent::__construct($message);
    }
}

/** Root-owned public metadata; this class never writes configuration or credentials. */
final class WizardFiles
{
    public function __construct(private readonly string $directory = '/var/lib/gitreposted-installer') {}

    public function read(string $name): array
    {
        if (!in_array($name, ['public.json', 'access.json'], true)
            || realpath($this->directory) !== $this->directory || is_link($this->directory)) {
            throw new \RuntimeException('Installer state is unavailable.');
        }
        $path = $this->directory . '/' . $name;
        $directoryStat = stat($this->directory);
        $fileStat = !is_link($path) && is_file($path) ? stat($path) : false;
        if ($directoryStat === false || $fileStat === false || $directoryStat['uid'] !== 0 || $fileStat['uid'] !== 0
            || ($directoryStat['mode'] & 0022) !== 0 || ($fileStat['mode'] & 0022) !== 0
            || $fileStat['size'] > 16384 || realpath($path) !== $path) {
            throw new \RuntimeException('Installer state is unavailable.');
        }
        $raw = file_get_contents($path, false, null, 0, 16385);
        $result = is_string($raw) ? json_decode($raw, true, 12, JSON_THROW_ON_ERROR) : null;
        if (!is_array($result) || array_is_list($result)) throw new \RuntimeException('Invalid installer state.');
        return $result;
    }

    public function sessions(): string
    {
        $path = $this->directory . '/sessions';
        $info = !is_link($path) && is_dir($path) ? stat($path) : false;
        if ($info === false || realpath($path) !== $path || ($info['mode'] & 0777) !== 0700
            || !function_exists('posix_geteuid') || $info['uid'] !== posix_geteuid()) {
            throw new \RuntimeException('Installer sessions are unavailable.');
        }
        return $path;
    }
}

/** One bounded request/response, without a shell, environment values or credential arguments. */
final class WizardBroker
{
    public function __construct(private readonly string $socket = '/var/lib/gitreposted-installer/broker.sock') {}

    public function __invoke(string $action, array $payload): array
    {
        if (!in_array($action, ['status', 'enroll', 'check_bot', 'start', 'revise', 'retry', 'host'], true)) {
            throw new \RuntimeException('Unsupported broker action.');
        }
        $timeout = $action === 'check_bot' ? 45 : ($action === 'revise' ? 25 : 5);
        $connection = @stream_socket_client('unix://' . $this->socket, $code, $message, $timeout, STREAM_CLIENT_CONNECT);
        if ($connection === false) throw new \RuntimeException('Installer broker unavailable.');
        try {
            stream_set_timeout($connection, $timeout);
            $request = json_encode(['action' => $action, 'payload' => (object) $payload], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\n";
            if (strlen($request) > 32768) throw new \RuntimeException('Broker request exceeds its bound.');
            $offset = 0;
            $deadline = microtime(true) + $timeout;
            while ($offset < strlen($request)) {
                $written = fwrite($connection, substr($request, $offset));
                if ($written === false || $written === 0 || microtime(true) > $deadline) throw new \RuntimeException('Broker write failed.');
                $offset += $written;
            }
            $response = fgets($connection, 65537);
            $metadata = stream_get_meta_data($connection);
            if (!is_string($response) || !str_ends_with($response, "\n") || strlen($response) > 65536 || !empty($metadata['timed_out'])) {
                throw new \RuntimeException('Broker response unavailable.');
            }
            $decoded = json_decode($response, true, 18, JSON_THROW_ON_ERROR);
            if (!is_array($decoded) || !is_bool($decoded['ok'] ?? null)) throw new \RuntimeException('Invalid broker response.');
            return $decoded;
        } finally {
            fclose($connection);
        }
    }
}

/** Private per-IP counters. REMOTE_ADDR is supplied by the web server, never a forwarded header. */
final class WizardRateLimit
{
    public function __construct(private readonly string $directory) {}

    public function __invoke(string $scope, string $identity, int $limit, int $seconds, int $now): bool
    {
        if (realpath($this->directory) !== $this->directory || is_link($this->directory)) return false;
        $lockPath = $this->directory . '/.rate-cleanup.lock';
        if (is_link($lockPath)) return false;
        $directoryLock = @fopen($lockPath, 'c+b');
        if ($directoryLock === false) return false;
        try {
            if (!flock($directoryLock, LOCK_SH) || !chmod($lockPath, 0600)) return false;
            return $this->consume($scope, $identity, $limit, $seconds, $now);
        } finally {
            flock($directoryLock, LOCK_UN);
            fclose($directoryLock);
        }
    }

    private function consume(string $scope, string $identity, int $limit, int $seconds, int $now): bool
    {
        $path = $this->directory . '/rate-' . hash('sha256', $scope . ':' . $identity);
        if (is_link($path)) return false;
        $handle = @fopen($path, 'c+b');
        if ($handle === false) return false;
        try {
            if (!flock($handle, LOCK_EX) || !chmod($path, 0600)) return false;
            $raw = stream_get_contents($handle, 2049);
            $data = is_string($raw) ? json_decode($raw, true) : null;
            if (!is_array($data) || !is_int($data['since'] ?? null) || $data['since'] <= $now - $seconds || $data['since'] > $now) {
                $data = ['since' => $now, 'count' => 0];
            }
            $data['count'] = min($limit + 1, max(0, (int) ($data['count'] ?? 0)) + 1);
            $encoded = json_encode($data, JSON_THROW_ON_ERROR);
            rewind($handle);
            if (!ftruncate($handle, 0) || fwrite($handle, $encoded) !== strlen($encoded) || !fflush($handle)) return false;
            return $data['count'] <= $limit;
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }
}

/** Pure HTTP controller: all filesystem, clock, session rotation and root transport are adapters. */
final class Wizard
{
    private array $session;
    private readonly \Closure $read;
    private readonly \Closure $broker;
    private readonly \Closure $limit;
    private readonly \Closure $clock;
    private readonly \Closure $rotate;

    public function __construct(callable $read, callable $broker, callable $limit, array &$session, ?callable $clock = null, ?callable $rotate = null)
    {
        $this->read = \Closure::fromCallable($read);
        $this->broker = \Closure::fromCallable($broker);
        $this->limit = \Closure::fromCallable($limit);
        $this->session =& $session;
        $this->clock = $clock === null ? static fn(): int => time() : \Closure::fromCallable($clock);
        $this->rotate = $rotate === null ? static fn(): bool => true : \Closure::fromCallable($rotate);
    }

    public static function secure(array $server): bool
    {
        return in_array($server['HTTPS'] ?? null, ['on', '1', 1, true], true);
    }

    public static function trustedHost(array $server, array $public): bool
    {
        $authority = self::authority((string) ($server['HTTP_HOST'] ?? ''));
        $base = parse_url((string) ($public['base_url'] ?? ''));
        if ($authority === null || !is_array($base) || !isset($base['host']) || isset($base['user']) || isset($base['pass'])
            || !in_array($base['scheme'] ?? '', ['http', 'https'], true)
            || !in_array($base['path'] ?? '', ['', '/'], true) || isset($base['query']) || isset($base['fragment'])) return false;
        $configuredHost = self::hostText((string) $base['host']);
        $publicHost = self::hostText((string) ($public['host'] ?? ''));
        $allowed = (array) ($public['allowed_hosts'] ?? [$publicHost]);
        $allowed = array_map(static fn(mixed $host): string => is_string($host) ? self::hostText($host) : '', $allowed);
        if ($configuredHost === '' || $publicHost !== $configuredHost || !in_array($authority['host'], $allowed, true)) return false;
        $default = self::secure($server) ? 443 : 80;
        $port = (int) ($base['port'] ?? $default);
        return $authority['port'] === null || $authority['port'] === $port;
    }

    public function handle(string $method, string $action, array $server, string $raw = ''): array
    {
        $headers = ['Content-Type' => 'application/json; charset=utf-8', 'Cache-Control' => 'no-store, private',
            'Referrer-Policy' => 'no-referrer', 'X-Content-Type-Options' => 'nosniff', 'X-Frame-Options' => 'DENY',
            'Content-Security-Policy' => "default-src 'none'; frame-ancestors 'none'; base-uri 'none'", 'Pragma' => 'no-cache'];
        try {
            $public = ($this->read)('public.json');
            if (!is_array($public) || !is_bool($public['installed'] ?? null) || !is_bool($public['tls_ready'] ?? null)
                || !self::trustedHost($server, $public)) throw new WizardError('INVALID_HOST', 'Откройте мастер по адресу, показанному в SSH.', 403);
            $secure = self::secure($server) && $public['tls_ready'] === true;
            $authenticated = $secure && $this->authenticated();
            if ($method === 'GET' && $action === 'status') {
                $broker = null;
                if ($authenticated && !$public['installed']) {
                    $this->rate('status', $server, 120, 60);
                    $broker = $this->call('status', []);
                    // Job and host/completion metadata must describe the same root checkpoint.
                    // Never spread arbitrary broker fields into the HTTP response.
                    $fresh = array_intersect_key($broker, array_flip(['installed', 'tls_ready', 'base_url', 'host',
                        'public_ip', 'site_url', 'site_host', 'allowed_hosts']));
                    $public = array_replace($public, $fresh);
                    if (!is_bool($public['installed'] ?? null) || !is_bool($public['tls_ready'] ?? null)
                        || !self::trustedHost($server, $public)) throw new \RuntimeException('Invalid root status.');
                    $secure = self::secure($server) && $public['tls_ready'] === true;
                }
                $result = ['authenticated' => $authenticated && !$public['installed'], 'secure' => $secure,
                    'installed' => $public['installed'], 'base_url' => (string) $public['base_url'], 'host' => (string) $public['host'],
                    'public_ip' => (string) ($public['public_ip'] ?? ''), 'tls_ready' => $public['tls_ready'],
                    'site_url' => (string) ($public['site_url'] ?? $public['base_url']),
                    'site_host' => (string) ($public['site_host'] ?? $public['host']), 'job' => null];
                $result['admin_url'] = rtrim($result['site_url'], '/') . '/control/';
                if ($authenticated && !$public['installed']) {
                    $result['csrf'] = $this->session['csrf'];
                    $result['job'] = $this->job($broker['job'] ?? null);
                }
                return ['status' => 200, 'headers' => $headers, 'body' => ['ok' => true, 'result' => $result]];
            }
            if ($method !== 'POST') throw new WizardError('METHOD_NOT_ALLOWED', 'Этот метод не поддерживается.', 405);
            if ($public['installed']) throw new WizardError('INSTALLED', 'Установка завершена. Мастер закрыт.', 410);
            if (!$secure) throw new WizardError('HTTPS_REQUIRED', 'Сначала настройте HTTPS. Не вводите секреты через HTTP.', 403);
            $this->origin($server, 'https://' . (string) $server['HTTP_HOST']);
            if (!in_array($action, ['login', 'logout', 'check_bot', 'start', 'revise', 'retry', 'host'], true)) throw new WizardError('INVALID_ACTION', 'Неизвестное действие.', 404);
            if ($action !== 'login') {
                if (!$authenticated) throw new WizardError('AUTH_REQUIRED', 'Откройте ссылку установки из SSH-консоли.', 401);
                $csrf = (string) ($server['HTTP_X_CSRF_TOKEN'] ?? '');
                if (strlen($csrf) !== 64 || !hash_equals((string) $this->session['csrf'], $csrf)) throw new WizardError('CSRF_FAILED', 'Обновите страницу мастера и повторите действие.', 403);
            }
            $payload = $this->json($raw, $server);
            if ($action === 'login') {
                $this->only($payload, ['code']);
                $this->rate('login', $server, 10, 300);
                if (!(($this->limit)('login-global', 'all', 60, 300, ($this->clock)()))) throw new WizardError('RATE_LIMITED', 'Слишком много попыток. Повторите через несколько минут.', 429);
                $code = $this->string($payload['code'] ?? null, 8, 160);
                $access = ($this->read)('access.json');
                if (!is_array($access) || !is_int($access['expires_at'] ?? null) || $access['expires_at'] < ($this->clock)()
                    || !is_string($access['code_hash'] ?? null) || !password_verify($code, $access['code_hash'])) {
                    throw new WizardError('INVALID_CODE', 'Код неверен или срок его действия закончился.', 401);
                }
                if (($this->call('enroll', ['code' => $code])['enrolled'] ?? false) !== true) throw new \RuntimeException('Enrollment failed.');
                $this->session = [];
                if (!(($this->rotate)())) throw new \RuntimeException('Session rotation failed.');
                $this->session = ['authenticated' => true, 'created_at' => ($this->clock)(), 'last_activity' => ($this->clock)(),
                    'csrf' => bin2hex(random_bytes(32))];
                $result = ['authenticated' => true, 'csrf' => $this->session['csrf']];
            } elseif ($action === 'logout') {
                $this->only($payload, []);
                $this->session = [];
                ($this->rotate)();
                $result = ['authenticated' => false];
            } elseif ($action === 'check_bot') {
                $this->only($payload, ['platform', 'token']);
                $this->rate('check_bot', $server, 12, 60);
                $platform = $payload['platform'] ?? null;
                if (!in_array($platform, ['telegram', 'max'], true)) throw new WizardError('INVALID_SETTINGS', 'Выберите платформу бота.');
                $token = $this->token($platform, $payload['token'] ?? null);
                $checked = $this->call('check_bot', ['platform' => $platform, 'token' => $token]);
                $identity = is_array($checked['identity'] ?? null) ? $checked['identity'] : [];
                $result = ['identity' => ['id' => $this->safeText($identity['id'] ?? '', 32), 'username' => $this->safeText($identity['username'] ?? '', 128),
                    'name' => $this->safeText($identity['name'] ?? '', 160)], 'existing_urls' => []];
                foreach (array_slice((array) ($checked['existing_urls'] ?? []), 0, 20) as $url) {
                    if (is_string($url) && strlen($url) <= 2048 && filter_var($url, FILTER_VALIDATE_URL) && in_array(parse_url($url, PHP_URL_SCHEME), ['http', 'https'], true)) $result['existing_urls'][] = $url;
                }
            } elseif ($action === 'start' || $action === 'revise') {
                $this->only($payload, $action === 'revise' ? ['job_id', 'settings'] : ['settings']);
                $this->rate('start', $server, 6, 300);
                $request = ['settings' => $this->settings($payload['settings'] ?? null)];
                if ($action === 'revise') {
                    $request['job_id'] = $this->string($payload['job_id'] ?? null, 1, 100);
                    if (preg_match('/^[a-zA-Z0-9_-]+$/D', $request['job_id']) !== 1) throw new WizardError('INVALID_SETTINGS', 'Некорректный номер установки.');
                }
                $result = ['job' => $this->job($this->call($action, $request)['job'] ?? null)];
            } elseif ($action === 'retry') {
                $this->only($payload, ['job_id']);
                $this->rate('retry', $server, 10, 300);
                $id = $this->string($payload['job_id'] ?? null, 1, 100);
                if (preg_match('/^[a-zA-Z0-9_-]+$/D', $id) !== 1) throw new WizardError('INVALID_SETTINGS', 'Некорректный номер установки.');
                $result = ['job' => $this->job($this->call('retry', ['job_id' => $id])['job'] ?? null)];
            } else {
                $this->only($payload, ['host', 'email']);
                $this->rate('host', $server, 5, 300);
                $host = self::hostText($this->string($payload['host'] ?? null, 1, 253));
                $ip = filter_var($host, FILTER_VALIDATE_IP);
                if ($ip !== false) {
                    if ($host !== self::hostText((string) ($public['public_ip'] ?? ''))) throw new WizardError('INVALID_SETTINGS', 'Для IP-сертификата используйте IP этого сервера.');
                } elseif (preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $host) !== 1) {
                    throw new WizardError('INVALID_SETTINGS', 'Введите домен без протокола, пути и порта.');
                }
                $email = $this->string($payload['email'] ?? '', 0, 254);
                if ($email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL) === false) throw new WizardError('INVALID_SETTINGS', 'Проверьте адрес электронной почты.');
                $result = ['job' => $this->job($this->call('host', ['host' => $host, 'email' => $email])['job'] ?? null),
                    'base_url' => (string) $public['base_url'], 'reconnect' => false];
            }
            return ['status' => 200, 'headers' => $headers, 'body' => ['ok' => true, 'result' => $result]];
        } catch (WizardError $error) {
            if ($error->status === 405) $headers['Allow'] = 'GET, POST';
            if ($error->status === 429) $headers['Retry-After'] = '300';
            return ['status' => $error->status, 'headers' => $headers, 'body' => ['ok' => false, 'error' => ['code' => $error->errorCode, 'message' => $error->getMessage()]]];
        } catch (\Throwable) {
            return ['status' => 503, 'headers' => $headers, 'body' => ['ok' => false, 'error' => ['code' => 'UNAVAILABLE', 'message' => 'Мастер временно недоступен. Повторите запрос или проверьте состояние установки через SSH.']]];
        }
    }

    private function authenticated(): bool
    {
        $now = ($this->clock)();
        if (($this->session['authenticated'] ?? null) !== true || !is_int($this->session['created_at'] ?? null)
            || !is_int($this->session['last_activity'] ?? null) || $this->session['created_at'] > $now
            || $this->session['created_at'] < $now - 3600 || $this->session['last_activity'] < $now - 1800
            || preg_match('/^[a-f0-9]{64}$/D', (string) ($this->session['csrf'] ?? '')) !== 1) {
            $this->session = [];
            return false;
        }
        $this->session['last_activity'] = $now;
        return true;
    }

    private function origin(array $server, string $base): void
    {
        $origin = (string) ($server['HTTP_ORIGIN'] ?? '');
        $expected = $this->originText($base);
        if ($origin === '' || $expected === '' || str_contains($origin, ',') || $this->originText($origin) !== $expected
            || !in_array((string) ($server['HTTP_SEC_FETCH_SITE'] ?? 'same-origin'), ['same-origin', 'none'], true)) {
            throw new WizardError('INVALID_ORIGIN', 'Откройте мастер в исходном окне браузера.', 403);
        }
    }

    private function originText(string $value): string
    {
        $parsed = parse_url($value);
        if (!is_array($parsed) || ($parsed['scheme'] ?? '') !== 'https' || !isset($parsed['host'])
            || isset($parsed['user']) || isset($parsed['pass']) || isset($parsed['query']) || isset($parsed['fragment'])
            || !in_array($parsed['path'] ?? '', ['', '/'], true)) return '';
        $host = self::hostText($parsed['host']);
        return $host === '' ? '' : 'https://' . $host . ':' . (int) ($parsed['port'] ?? 443);
    }

    private static function hostText(string $host): string
    {
        return strtolower(trim($host, '[]'));
    }

    private static function authority(string $authority): ?array
    {
        if ($authority === '' || strlen($authority) > 260 || preg_match('~[\x00-\x20\x7f/@\\\\%?#]~', $authority) === 1) return null;
        $parsed = parse_url('https://' . $authority);
        if (!is_array($parsed) || !isset($parsed['host']) || isset($parsed['user']) || isset($parsed['path']) || isset($parsed['query']) || isset($parsed['fragment'])) return null;
        return ['host' => self::hostText($parsed['host']), 'port' => $parsed['port'] ?? null];
    }

    private function json(string $raw, array $server): array
    {
        if (strlen($raw) > 32768) throw new WizardError('BODY_TOO_LARGE', 'Запрос слишком большой.', 413);
        if (preg_match('~^application/json(?:\s*;[^\r\n]*)?$~iD', (string) ($server['CONTENT_TYPE'] ?? '')) !== 1) throw new WizardError('JSON_REQUIRED', 'Ожидается JSON-запрос.', 415);
        try { $decoded = json_decode($raw, true, 12, JSON_THROW_ON_ERROR); }
        catch (\JsonException) { throw new WizardError('INVALID_JSON', 'Проверьте введённые значения.'); }
        if (!is_array($decoded) || !str_starts_with(ltrim($raw), '{')) throw new WizardError('INVALID_JSON', 'Ожидается объект настроек.');
        return $decoded;
    }

    private function rate(string $scope, array $server, int $limit, int $seconds): void
    {
        $ip = (string) ($server['REMOTE_ADDR'] ?? '');
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) $ip = 'unknown';
        if (!(($this->limit)($scope, $ip, $limit, $seconds, ($this->clock)()))) throw new WizardError('RATE_LIMITED', 'Слишком много запросов. Повторите через несколько минут.', 429);
    }

    private function call(string $action, array $payload): array
    {
        $result = ($this->broker)($action, $payload);
        if (!is_array($result) || ($result['ok'] ?? false) !== true) {
            $code = is_array($result) ? strtoupper((string) ($result['error']['code'] ?? '')) : '';
            throw new WizardError(preg_match('/^[A-Z0-9_]{1,64}$/D', $code) === 1 ? $code : 'BROKER_FAILED', $this->brokerMessage($code), 409);
        }
        if (!is_array($result['result'] ?? null)) throw new \RuntimeException('Invalid broker result.');
        return $result['result'];
    }

    private function brokerMessage(string $code): string
    {
        return match ($code) {
            'INVALID_TOKEN', 'BOT_CHECK_FAILED' => 'Бот не подтвердил токен. Проверьте значение и доступность API.',
            'TAKEOVER_REQUIRED' => 'У бота уже настроен другой webhook. Явно подтвердите его переключение.',
            'INSTALL_BUSY', 'BUSY' => 'Установка уже выполняется. Дождитесь результата.',
            'INSTALLED', 'LOCKED' => 'Установка завершена. Мастер закрыт.',
            'REVISE_DENIED' => 'Включение ботов уже начиналось. Продолжите завершение существующей установки.',
            'REGISTERED_BOT_CHANGE_DENIED' => 'Подключение этого бота уже начиналось. Оставьте платформу включённой и используйте токен того же бота. Сменить или отключить бота можно в админке после завершения установки.',
            'INTERRUPTED' => 'Установка прервана. Можно продолжить сохранённую задачу.',
            'CODE_USED', 'CODE_EXPIRED' => 'Одноразовый код уже использован или устарел. Выпустите новый код через SSH командой bootstrap.sh --resume.',
            'INVALID_SETTINGS', 'VALIDATION_FAILED' => 'Проверьте настройки установки.',
            'HOST_INVALID', 'DNS_MISMATCH' => 'Проверьте домен и его DNS-записи: он должен вести на этот сервер.',
            'CERTIFICATE_FAILED', 'TLS_FAILED' => 'Не удалось получить сертификат. Проверьте DNS и доступность портов 80/443.',
            default => 'Не удалось завершить действие. Проверьте состояние установки и повторите запрос.',
        };
    }

    private function job(mixed $job): ?array
    {
        if ($job === null) return null;
        if (!is_array($job) || !in_array($job['status'] ?? '', ['idle', 'running', 'failed', 'complete'], true)) throw new \RuntimeException('Invalid broker job.');
        $id = (string) ($job['id'] ?? '');
        if ($id !== '' && preg_match('/^[a-zA-Z0-9_-]{1,100}$/D', $id) !== 1) throw new \RuntimeException('Invalid job identifier.');
        $type = $job['type'] ?? 'install';
        if (!in_array($type, ['install', 'host'], true)) throw new \RuntimeException('Invalid job type.');
        $result = ['id' => $id, 'type' => $type, 'status' => $job['status'], 'steps' => [], 'error' => null,
            'can_revise' => ($job['can_revise'] ?? false) === true];
        foreach (array_slice((array) ($job['steps'] ?? []), 0, 40) as $step) {
            if (!is_array($step) || !in_array($step['status'] ?? '', ['pending', 'running', 'done', 'skipped', 'failed'], true)) throw new \RuntimeException('Invalid job step.');
            $result['steps'][] = ['id' => $this->safeText($step['id'] ?? '', 64), 'title' => $this->safeText($step['title'] ?? '', 160), 'status' => $step['status']];
        }
        if (!empty($job['error'])) {
            $code = is_array($job['error']) ? strtoupper((string) ($job['error']['code'] ?? 'JOB_FAILED')) : 'JOB_FAILED';
            $result['error'] = ['code' => preg_match('/^[A-Z0-9_]{1,64}$/D', $code) === 1 ? $code : 'JOB_FAILED', 'message' => $this->brokerMessage($code)];
        }
        return $result;
    }

    public function settings(mixed $settings): array
    {
        $settings = $this->object($settings);
        $this->only($settings, ['admin', 'telegram', 'max', 'timezone', 'support_username', 'hcaptcha', 'mtproto']);
        $admin = $this->object($settings['admin'] ?? null);
        $this->only($admin, ['username', 'password', 'password_confirm']);
        $username = $this->string($admin['username'] ?? null, 3, 64);
        if (preg_match('/^[A-Za-z0-9_.@-]+$/D', $username) !== 1) throw new WizardError('INVALID_SETTINGS', 'Логин администратора: 3–64 латинских символа, цифры, точка, @, _ или дефис.');
        $password = $this->string($admin['password'] ?? null, 12, 72, false);
        if (preg_match('//u', $password) !== 1 || preg_match_all('/./us', $password) < 12) throw new WizardError('INVALID_SETTINGS', 'Пароль должен содержать не менее 12 символов и не более 72 байт.');
        $confirmation = $this->string($admin['password_confirm'] ?? null, 12, 72, false);
        if (!hash_equals($password, $confirmation)) throw new WizardError('INVALID_SETTINGS', 'Пароли администратора не совпадают.');
        $out = ['admin' => ['username' => $username, 'password' => $password, 'password_confirm' => $confirmation]];
        foreach (['telegram', 'max'] as $platform) {
            $value = $this->object($settings[$platform] ?? null);
            $this->only($value, ['enabled', 'token', 'takeover']);
            $enabled = $this->boolean($value['enabled'] ?? null);
            $takeover = $this->boolean($value['takeover'] ?? false);
            $out[$platform] = ['enabled' => $enabled, 'token' => $enabled ? $this->token($platform, $value['token'] ?? null) : '', 'takeover' => $enabled && $takeover];
        }
        $timezone = $this->string($settings['timezone'] ?? 'Europe/Moscow', 1, 64);
        if (!in_array($timezone, timezone_identifiers_list(\DateTimeZone::ALL_WITH_BC), true)) throw new WizardError('INVALID_SETTINGS', 'Выберите существующий часовой пояс.');
        $support = $this->string($settings['support_username'] ?? '', 0, 32);
        $support = ltrim($support, '@');
        if ($support !== '' && preg_match('/^[A-Za-z0-9_]{5,32}$/D', $support) !== 1) throw new WizardError('INVALID_SETTINGS', 'Контакт поддержки: Telegram username без ссылки.');
        $out['timezone'] = $timezone;
        $out['support_username'] = $support;
        $captcha = $this->object($settings['hcaptcha'] ?? ['enabled' => false]);
        $this->only($captcha, ['enabled', 'sitekey', 'secret']);
        $captchaEnabled = $this->boolean($captcha['enabled'] ?? null);
        $sitekey = $captchaEnabled ? $this->string($captcha['sitekey'] ?? null, 36, 36) : '';
        $secret = $captchaEnabled ? $this->string($captcha['secret'] ?? null, 23, 131) : '';
        if ($captchaEnabled && (preg_match('/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/Di', $sitekey) !== 1 || preg_match('/^ES_[A-Za-z0-9_-]{20,128}$/D', $secret) !== 1)) throw new WizardError('INVALID_SETTINGS', 'Проверьте sitekey и secret hCaptcha.');
        $out['hcaptcha'] = ['enabled' => $captchaEnabled, 'sitekey' => $sitekey, 'secret' => $secret];
        $mtproto = $this->object($settings['mtproto'] ?? ['enabled' => false]);
        $this->only($mtproto, ['enabled', 'api_id', 'api_hash']);
        $mtEnabled = $this->boolean($mtproto['enabled'] ?? null);
        if ($mtEnabled) throw new WizardError('INVALID_SETTINGS', 'Локальный Bot API настраивается отдельно после установки.');
        $apiId = $mtEnabled ? ($mtproto['api_id'] ?? null) : 0;
        $apiHash = $mtEnabled ? $this->string($mtproto['api_hash'] ?? null, 32, 32) : '';
        if ($mtEnabled && (!$out['telegram']['enabled'] || !is_int($apiId) || $apiId < 1 || $apiId > 2147483647 || preg_match('/^[a-f0-9]{32}$/Di', $apiHash) !== 1)) throw new WizardError('INVALID_SETTINGS', 'Для импорта Telegram включите бота и укажите API ID/hash приложения.');
        $out['mtproto'] = ['enabled' => $mtEnabled, 'api_id' => $apiId, 'api_hash' => $apiHash];
        return $out;
    }

    private function token(string $platform, mixed $value): string
    {
        $token = $this->string($value, 16, $platform === 'telegram' ? 220 : 4096);
        $pattern = $platform === 'telegram' ? '/^[0-9]{6,12}:[A-Za-z0-9_-]{30,200}$/D' : '/^[\x21-\x7e]{16,4096}$/D';
        if (preg_match($pattern, $token) !== 1) throw new WizardError('INVALID_SETTINGS', 'Проверьте формат токена бота.');
        return $token;
    }

    private function only(array $value, array $allowed): void
    {
        if (array_diff(array_keys($value), $allowed) !== []) throw new WizardError('INVALID_SETTINGS', 'Запрос содержит неизвестные настройки.');
    }

    private function object(mixed $value): array
    {
        if (!is_array($value) || ($value !== [] && array_is_list($value))) throw new WizardError('INVALID_SETTINGS', 'Проверьте структуру настроек.');
        return $value;
    }

    private function boolean(mixed $value): bool
    {
        if (!is_bool($value)) throw new WizardError('INVALID_SETTINGS', 'Переключатель должен иметь значение true или false.');
        return $value;
    }

    private function string(mixed $value, int $min, int $max, bool $trim = true): string
    {
        if (!is_string($value)) throw new WizardError('INVALID_SETTINGS', 'Заполните обязательные поля.');
        if ($trim) $value = trim($value);
        if (strlen($value) < $min || strlen($value) > $max || preg_match('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/', $value) === 1) throw new WizardError('INVALID_SETTINGS', 'Проверьте длину и формат введённых значений.');
        return $value;
    }

    private function safeText(mixed $value, int $limit): string
    {
        if (!is_string($value) && !is_int($value)) return '';
        $text = preg_replace('/[\x00-\x1f\x7f]/', '', (string) $value) ?? '';
        return function_exists('mb_strcut') ? mb_strcut($text, 0, $limit, 'UTF-8') : substr($text, 0, $limit);
    }
}
