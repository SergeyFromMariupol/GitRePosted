<?php

declare(strict_types=1);

use GitRePostedInstaller\Wizard;
use GitRePostedInstaller\WizardBroker;
use GitRePostedInstaller\WizardFiles;
use GitRePostedInstaller\WizardRateLimit;

require dirname(__DIR__) . '/lib/Wizard.php';

ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.use_trans_sid', '0');
ini_set('session.cookie_httponly', '1');
$newSession = false;

try {
    $files = new WizardFiles();
    $public = $files->read('public.json');
    if (!Wizard::trustedHost($_SERVER, $public)) {
        http_response_code(403);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        echo '{"ok":false,"error":{"code":"INVALID_HOST","message":"Откройте мастер по адресу из SSH."}}';
        exit;
    }
    $session = [];
    $action = $_GET['action'] ?? 'status';
    if (!is_string($action) || preg_match('/^[a-z_]{1,20}$/D', $action) !== 1) $action = 'invalid';
    $sessionPath = ($public['installed'] ?? false) === true ? null : $files->sessions();
    $cookie = $_COOKIE['gitreposted_setup'] ?? '';
    $existingSession = $sessionPath !== null && is_string($cookie) && preg_match('/^[A-Za-z0-9,-]{22,128}$/D', $cookie) === 1
        && !is_link($sessionPath . '/sess_' . $cookie) && is_file($sessionPath . '/sess_' . $cookie);
    // Anonymous status requests must not create an unbounded collection of
    // private session files. Enrollment is the only operation opening a session.
    $openingSession = $action === 'login' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST';
    if (Wizard::secure($_SERVER) && $sessionPath !== null && ($existingSession || $openingSession)) {
        session_name('gitreposted_setup');
        session_save_path($sessionPath);
        session_set_cookie_params(['lifetime' => 0, 'path' => '/install/', 'secure' => true, 'httponly' => true, 'samesite' => 'Strict']);
        if (!session_start()) throw new RuntimeException('Installer session unavailable.');
        $newSession = !$existingSession;
        $session =& $_SESSION;
    }
    $limiter = $sessionPath === null ? static fn(): bool => false : new WizardRateLimit($sessionPath);
    $controller = new Wizard([$files, 'read'], new WizardBroker(), $limiter, $session,
        rotate: static fn(): bool => session_status() === PHP_SESSION_ACTIVE && session_regenerate_id(true));
    $input = file_get_contents('php://input', false, null, 0, 32769);
    $response = $controller->handle((string) ($_SERVER['REQUEST_METHOD'] ?? ''), $action, $_SERVER, is_string($input) ? $input : '');
    if (session_status() === PHP_SESSION_ACTIVE) {
        if ($newSession && ($_SESSION['authenticated'] ?? false) !== true) session_destroy();
        else session_write_close();
    }
    http_response_code($response['status']);
    foreach ($response['headers'] as $name => $value) header($name . ': ' . $value);
    echo json_encode($response['body'], JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
} catch (Throwable) {
    if (session_status() === PHP_SESSION_ACTIVE) {
        if ($newSession && ($_SESSION['authenticated'] ?? false) !== true) session_destroy();
        else session_write_close();
    }
    http_response_code(503);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('Referrer-Policy: no-referrer');
    echo '{"ok":false,"error":{"code":"UNAVAILABLE","message":"Мастер недоступен. Проверьте состояние установки через SSH."}}';
}
