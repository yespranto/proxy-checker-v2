<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/Config.php';
require_once __DIR__ . '/../src/Http.php';

$expected = Config::echoToken();
$provided = (string) ($_GET['t'] ?? '');

if ($expected === '' || $provided === '' || !hash_equals($expected, $provided)) {
    Http::error('Forbidden.', 403);
}

$headers = [];
foreach ($_SERVER as $key => $val) {
    if (!str_starts_with($key, 'HTTP_') || !is_string($val)) {
        continue;
    }
    $name = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($key, 5)))));
    $lower = strtolower($name);
    if (in_array($lower, ['cookie', 'authorization', 'x-csrf-token'], true)) {
        continue;
    }
    $headers[$name] = $val;
}

Http::json([
    'ip' => Http::clientIp(),
    'headers' => $headers,
]);
