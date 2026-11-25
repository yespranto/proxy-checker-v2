<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/Config.php';
require_once __DIR__ . '/../src/Db.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

try {
    $pdo = Db::pdo();
    $ok = $pdo->query('SELECT 1')->fetchColumn() === 1;
    if (!$ok) {
        http_response_code(503);
        echo json_encode(['ok' => false, 'db' => false], JSON_THROW_ON_ERROR);
        exit;
    }
    echo json_encode(['ok' => true, 'db' => true], JSON_THROW_ON_ERROR);
} catch (Throwable $e) {
    error_log('healthcheck failed: ' . $e->getMessage());
    http_response_code(503);
    echo json_encode(['ok' => false, 'db' => false]);
}
