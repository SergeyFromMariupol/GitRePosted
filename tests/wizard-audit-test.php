<?php
declare(strict_types=1);

require dirname(__DIR__) . '/lib/Wizard.php';

use GitRePostedInstaller\Wizard;

$failures = 0;
foreach (['install', 'host'] as $type) {
    $now = 1800000000;
    $initial = ['installed' => false, 'tls_ready' => true, 'host' => 'setup.example.org',
        'base_url' => 'https://setup.example.org', 'site_host' => 'setup.example.org',
        'site_url' => 'https://setup.example.org', 'allowed_hosts' => ['setup.example.org']];
    $new = [...$initial, 'installed' => $type === 'install', 'site_host' => 'posts.example.org',
        'site_url' => 'https://posts.example.org', 'allowed_hosts' => ['setup.example.org', 'posts.example.org'],
        'admin_url' => 'https://posts.example.org/control/',
        'job' => ['id' => 'committed-job', 'type' => $type, 'status' => 'complete',
            'steps' => [['id' => 'finish', 'title' => 'Завершение', 'status' => 'done']]]];
    $session = ['authenticated' => true, 'created_at' => $now, 'last_activity' => $now, 'csrf' => str_repeat('a', 64)];
    $controller = new Wizard(static fn(string $name): array => $initial,
        static fn(string $action, array $payload): array => ['ok' => true, 'result' => $new],
        static fn(): bool => true, $session, static fn(): int => $now);
    $response = $controller->handle('GET', 'status', ['HTTPS' => 'on', 'HTTP_HOST' => 'setup.example.org',
        'REMOTE_ADDR' => '192.0.2.10']);
    $result = $response['body']['result'] ?? [];
    $passed = $response['status'] === 200 && ($result['site_url'] ?? '') === $new['site_url']
        && ($result['installed'] ?? null) === $new['installed']
        && ($type !== 'install' || (($result['authenticated'] ?? null) === false && !isset($result['csrf'])));
    echo ($passed ? 'PASS ' : 'FAIL ') . $type . " commit between public snapshot and broker status uses latest metadata\n";
    if (!$passed) $failures++;
}

foreach (['valid', 'csrf', 'anonymous', 'bad-job', 'unknown-key'] as $case) {
    $now = 1800000000;
    $public = ['installed' => false, 'tls_ready' => true, 'host' => 'setup.example.org', 'base_url' => 'https://setup.example.org'];
    $session = $case === 'anonymous' ? [] : ['authenticated' => true, 'created_at' => $now, 'last_activity' => $now, 'csrf' => str_repeat('a', 64)];
    $settings = ['admin' => ['username' => 'operator', 'password' => 'fixture-new-password', 'password_confirm' => 'fixture-new-password'],
        'telegram' => ['enabled' => false, 'token' => 'discard-disabled-token', 'takeover' => false],
        'max' => ['enabled' => false, 'token' => 'discard-disabled-token', 'takeover' => false],
        'timezone' => 'UTC', 'support_username' => '', 'hcaptcha' => ['enabled' => false], 'mtproto' => ['enabled' => false]];
    $payload = ['job_id' => $case === 'bad-job' ? '../other' : 'original-job', 'settings' => $settings];
    if ($case === 'unknown-key') $payload['command'] = 'not-allowed';
    $calls = [];
    $controller = new Wizard(static fn(string $name): array => $public,
        static function(string $action, array $request) use (&$calls): array {
            $calls[] = [$action, $request];
            return ['ok' => true, 'result' => ['job' => ['id' => 'original-job', 'type' => 'install', 'status' => 'running', 'steps' => []]]];
        }, static fn(): bool => true, $session, static fn(): int => $now);
    $response = $controller->handle('POST', 'revise', ['HTTPS' => 'on', 'HTTP_HOST' => 'setup.example.org',
        'HTTP_ORIGIN' => 'https://setup.example.org', 'REMOTE_ADDR' => '192.0.2.10', 'CONTENT_TYPE' => 'application/json',
        'HTTP_X_CSRF_TOKEN' => str_repeat($case === 'csrf' ? 'b' : 'a', 64)], json_encode($payload, JSON_THROW_ON_ERROR));
    $expected = match ($case) { 'valid' => 200, 'csrf' => 403, 'anonymous' => 401, default => 400 };
    $passed = $response['status'] === $expected && ($case === 'valid'
        ? count($calls) === 1 && $calls[0][0] === 'revise' && $calls[0][1]['job_id'] === 'original-job'
            && $calls[0][1]['settings']['telegram']['token'] === '' && $calls[0][1]['settings']['max']['token'] === ''
            && !str_contains(json_encode($response), 'fixture-new-password')
        : $calls === []);
    echo ($passed ? 'PASS ' : 'FAIL ') . 'revise ' . $case . " enforces the authenticated bounded settings contract\n";
    if (!$passed) $failures++;
}
exit($failures === 0 ? 0 : 1);
