<?php

declare(strict_types=1);

require_once __DIR__ . '/src/Config.php';
require_once __DIR__ . '/src/Db.php';
require_once __DIR__ . '/src/Quota.php';
require_once __DIR__ . '/src/Http.php';

const LOGIN_MAX_FAILURES = 5;
const LOGIN_WINDOW_SECONDS = 900; // 15 minutes

function start_app_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    $isHttps = (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off')
        || (strtolower((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https');

    session_name('proxycheck_sid');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => $isHttps,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);

    session_start();

    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
}

function csrf_token(): string
{
    start_app_session();
    return (string) $_SESSION['csrf_token'];
}

function verify_csrf(): void
{
    start_app_session();
    $expected = (string) ($_SESSION['csrf_token'] ?? '');
    $provided = (string) ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($_POST['_csrf'] ?? ''));

    if ($expected === '' || $provided === '' || !hash_equals($expected, $provided)) {
        Http::error('Invalid or missing CSRF token.', 403);
    }
}

function is_logged_in(): bool
{
    start_app_session();
    return isset($_SESSION['user_id']) && is_int($_SESSION['user_id']) && $_SESSION['user_id'] > 0;
}

function current_user_id(): int
{
    start_app_session();
    return isset($_SESSION['user_id']) ? (int) $_SESSION['user_id'] : 0;
}

function current_user(): ?array
{
    if (!is_logged_in()) {
        return null;
    }
    return [
        'id' => (int) $_SESSION['user_id'],
        'username' => (string) ($_SESSION['username'] ?? ''),
        'role' => (string) ($_SESSION['role'] ?? 'user'),
    ];
}

function require_auth_api(bool $requireCsrfOnWrite = true): int
{
    if (!is_logged_in()) {
        Http::error('Authentication required.', 401);
    }
    if ($requireCsrfOnWrite) {
        $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
        if (in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            verify_csrf();
        }
    }
    return current_user_id();
}

function is_login_rate_limited(PDO $pdo, string $ip, string $username): bool
{
    $cutoff = time() - LOGIN_WINDOW_SECONDS;
    $stmt = $pdo->prepare(
        'SELECT COUNT(*) FROM login_attempts
         WHERE ip = :ip AND username = :u AND attempted_at >= :cutoff'
    );
    $stmt->execute([
        ':ip' => $ip,
        ':u' => strtolower($username),
        ':cutoff' => $cutoff,
    ]);
    return ((int) $stmt->fetchColumn()) >= LOGIN_MAX_FAILURES;
}

function record_login_failure(PDO $pdo, string $ip, string $username): void
{
    $now = time();
    $cutoff = $now - LOGIN_WINDOW_SECONDS;
    Db::writeTransaction($pdo, static function (PDO $conn) use ($ip, $username, $now, $cutoff): void {
        $del = $conn->prepare('DELETE FROM login_attempts WHERE attempted_at < :cutoff');
        $del->execute([':cutoff' => $cutoff]);

        $ins = $conn->prepare(
            'INSERT INTO login_attempts (ip, username, attempted_at) VALUES (:ip, :u, :t)'
        );
        $ins->execute([
            ':ip' => $ip,
            ':u' => strtolower($username),
            ':t' => $now,
        ]);
    });
}

function clear_login_failures(PDO $pdo, string $ip, string $username): void
{
    Db::writeTransaction($pdo, static function (PDO $conn) use ($ip, $username): void {
        $del = $conn->prepare('DELETE FROM login_attempts WHERE ip = :ip AND username = :u');
        $del->execute([
            ':ip' => $ip,
            ':u' => strtolower($username),
        ]);
    });
}

/**
 * Attempt login. Returns ['ok' => bool, 'error' => ?string, 'status' => int, 'user' => ?array].
 */
function attempt_login(string $username, string $password): array
{
    start_app_session();
    $username = trim($username);
    $ip = Http::clientIp();

    if ($username === '' || $password === '') {
        return ['ok' => false, 'error' => 'Username and password are required.', 'status' => 400, 'user' => null];
    }

    $pdo = Db::pdo();
    if (is_login_rate_limited($pdo, $ip, $username)) {
        return ['ok' => false, 'error' => 'Too many failed login attempts. Try again in 15 minutes.', 'status' => 429, 'user' => null];
    }

    $stmt = $pdo->prepare('SELECT id, username, password_hash, role FROM users WHERE username = :u LIMIT 1');
    $stmt->execute([':u' => $username]);
    $user = $stmt->fetch();

    $valid = $user && password_verify($password, (string) $user['password_hash']);
    if (!$valid) {
        record_login_failure($pdo, $ip, $username);
        return ['ok' => false, 'error' => 'Invalid credentials.', 'status' => 401, 'user' => null];
    }

    clear_login_failures($pdo, $ip, $username);
    session_regenerate_id(true);
    $_SESSION['user_id'] = (int) $user['id'];
    $_SESSION['username'] = (string) $user['username'];
    $_SESSION['role'] = (string) $user['role'];
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

    return [
        'ok' => true,
        'error' => null,
        'status' => 200,
        'user' => current_user(),
    ];
}

function logout_user(): void
{
    start_app_session();
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params['path'],
            $params['domain'],
            (bool) $params['secure'],
            (bool) $params['httponly']
        );
    }
    session_destroy();
}

function can_check(int $count = 1): bool
{
    $uid = current_user_id();
    if ($uid <= 0 || $count <= 0) {
        return false;
    }
    $status = Quota::status(Db::pdo(), $uid);
    return $status['remaining'] >= $count;
}

function use_checks(int $count = 1): bool
{
    $uid = current_user_id();
    if ($uid <= 0) {
        return false;
    }
    return Quota::reserve(Db::pdo(), $uid, $count);
}

function checks_remaining(): int
{
    $uid = current_user_id();
    if ($uid <= 0) {
        return 0;
    }
    return Quota::status(Db::pdo(), $uid)['remaining'];
}
