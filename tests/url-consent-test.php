<?php
declare(strict_types=1);

// Captured platform reads only. Config, SQL, real API and webhook mutations are forbidden.
require dirname(__DIR__) . '/bin/application.php';
foreach (['telegram', 'max'] as $platform) {
    $endpoint = $platform === 'telegram' ? '/webhooks/telegram' : '/webhooks/max';
    $base = 'https://selfhost.example';
    $cases = [
        [$base . $endpoint, $base . $endpoint],
        [$base . $endpoint . '?key=private-marker', $base . '/[configured-webhook]'],
        [$base . $endpoint . '?', $base . '/[configured-webhook]'],
        ['https://operator:private-marker@selfhost.example' . $endpoint, $base . '/[configured-webhook]'],
        [$base . $endpoint . '#private-marker', $base . '/[configured-webhook]'],
        [$base . '/private-marker', $base . '/[configured-webhook]'],
        ['https://selfhost.example:443' . $endpoint, 'https://selfhost.example:443' . $endpoint],
        ['HTTPS://selfhost.example' . $endpoint, $base . '/[configured-webhook]'],
    ];
    foreach ($cases as [$url, $expected]) {
        $calls = [];
        $transport = static function(string $service, string $token, string $method, string $path, array $body) use ($url, &$calls): array {
            $calls[] = $path;
            return match ($path) {
                'getMe' => ['ok'=>true, 'result'=>['id'=>123456, 'is_bot'=>true, 'username'=>'FixtureBot']],
                '/me' => ['user_id'=>987654, 'username'=>'FixtureBot'],
                'getWebhookInfo' => ['ok'=>true, 'result'=>['url'=>$url]],
                '/subscriptions' => ['subscriptions'=>[['url'=>$url]]],
                default => throw new RuntimeException('Unexpected mutation'),
            };
        };
        $token = $platform === 'telegram' ? '123456:' . str_repeat('t', 32) : 'fixture-max-token';
        $result = (new InstallerApplication($transport))->run(['action'=>'check', 'platform'=>$platform, 'token'=>$token]);
        if (($result['ok'] ?? false) !== true || $result['result']['existing_urls'] !== [$expected]) {
            throw new RuntimeException('Redaction collapsed a foreign URL into the configured URL');
        }
        if (str_contains(json_encode($result), 'private-marker')) throw new RuntimeException('Private URL component escaped');
    }
    echo 'PASS ', $platform, ' URL redaction preserves consent and excludes private components', "\n";
}

foreach (['not-a-url', 'ftp://selfhost.example/webhooks/telegram', 'https://selfhost.example:999999/webhooks/telegram'] as $url) {
    $transport = static fn(string $platform, string $token, string $method, string $path): array => $path === 'getMe'
        ? ['ok'=>true, 'result'=>['id'=>123456, 'is_bot'=>true, 'username'=>'FixtureBot']]
        : ['ok'=>true, 'result'=>['url'=>$url]];
    $result = (new InstallerApplication($transport))->run(['action'=>'check', 'platform'=>'telegram', 'token'=>'123456:'.str_repeat('t',32)]);
    if (($result['ok'] ?? true) !== false || ($result['error']['code'] ?? '') !== 'WEBHOOK_RESPONSE_INVALID') {
        throw new RuntimeException('Malformed webhook was silently reported as an empty subscription list');
    }
}
echo "PASS invalid platform URLs fail closed instead of hiding an existing subscription\n";
