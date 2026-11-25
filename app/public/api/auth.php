<?php

declare(strict_types=1);

require_once __DIR__ . '/../../auth.php';
require_once __DIR__ . '/../../src/Http.php';
require_once __DIR__ . '/../../src/Quota.php';

$method = Http::requireMethod('GET', 'POST');

if ($method === 'GET') {
    start_app_session();
    $user = current_user();
    if ($user === null) {
        Http::json([
            'ok' => true,
            'authenticated' => false,
            'csrf_token' => csrf_token(),
        ]);
    }
    Http::json([
        'ok' => true,
        'authenticated' => true,
        'user' => $user,
        'csrf_token' => csrf_token(),
        'quota' => Quota::status(Db::pdo(), (int) $user['id']),
    ]);
}

$action = (string) ($_GET['action'] ?? 'login');

if ($action === 'logout') {
    require_auth_api(true);
    logout_user();
    Http::json(['ok' => true]);
}

if ($action === 'login') {
    start_app_session();
    $contentType = strtolower((string) ($_SERVER['CONTENT_TYPE'] ?? ''));
    if (str_contains($contentType, 'application/json')) {
        $body = Http::readJsonBody(65536);
        $username = (string) ($body['username'] ?? '');
        $password = (string) ($body['password'] ?? '');
        $csrf = (string) ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($body['_csrf'] ?? ''));
    } else {
        $username = (string) ($_POST['username'] ?? '');
        $password = (string) ($_POST['password'] ?? '');
        $csrf = (string) ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($_POST['_csrf'] ?? ''));
    }

    $expected = (string) ($_SESSION['csrf_token'] ?? '');
    if ($expected === '' || $csrf === '' || !hash_equals($expected, $csrf)) {
        Http::error('Invalid or missing CSRF token.', 403);
    }

    $res = attempt_login($username, $password);
    if (!$res['ok']) {
        Http::error((string) $res['error'], (int) $res['status']);
    }

    Http::json([
        'ok' => true,
        'user' => $res['user'],
        'csrf_token' => csrf_token(),
        'quota' => Quota::status(Db::pdo(), (int) $res['user']['id']),
    ]);
}

Http::error('Unknown action.', 400);
