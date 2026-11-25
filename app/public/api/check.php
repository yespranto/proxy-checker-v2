<?php

declare(strict_types=1);

require_once __DIR__ . '/../../auth.php';
require_once __DIR__ . '/../../src/Http.php';
require_once __DIR__ . '/../../src/Parser.php';
require_once __DIR__ . '/../../src/Checker.php';
require_once __DIR__ . '/../../src/Crypto.php';
require_once __DIR__ . '/../../src/Quota.php';
require_once __DIR__ . '/../../src/ProxyStore.php';

Http::requireMethod('POST');
$userId = require_auth_api(true);

const SYNC_MAX_PROXIES = 10;

$body = Http::readJsonBody();
$timeout = max(3, min(30, (int) ($body['timeout'] ?? Config::checkTimeout())));
$retries = max(0, min(2, (int) ($body['retries'] ?? Config::checkRetries())));
$plainHttp = (bool) ($body['plain_http'] ?? false);

$pdo = Db::pdo();
$toCheck = [];
$parseErrors = [];

if (isset($body['ids']) && is_array($body['ids'])) {
    $ids = array_values(array_unique(array_filter(array_map('intval', $body['ids']), static fn (int $id): bool => $id > 0)));
    if ($ids === []) {
        Http::error('No valid proxy IDs provided.', 400);
    }
    if (count($ids) > SYNC_MAX_PROXIES) {
        Http::error('Sync check is limited to ' . SYNC_MAX_PROXIES . ' proxies. Use POST /api/jobs.php for larger batches.', 400);
    }

    $placeholders = implode(',', array_fill(0, count($ids), '?'));
    $stmt = $pdo->prepare(
        "SELECT id, host, port, type, username, password_enc
         FROM proxies
         WHERE user_id = ? AND id IN ({$placeholders})"
    );
    $stmt->execute(array_merge([$userId], $ids));
    foreach ($stmt->fetchAll() as $row) {
        $toCheck[] = [
            'id' => (int) $row['id'],
            'host' => (string) $row['host'],
            'port' => (int) $row['port'],
            'type' => (string) $row['type'],
            'username' => $row['username'] !== null ? (string) $row['username'] : null,
            'password' => Crypto::decrypt($row['password_enc'] !== null ? (string) $row['password_enc'] : null),
        ];
    }
    if ($toCheck === []) {
        Http::error('No matching proxies found.', 404);
    }
} elseif (isset($body['proxies'])) {
    $rawInput = is_array($body['proxies'])
        ? implode("\n", array_map('strval', $body['proxies']))
        : (string) $body['proxies'];
    $parsed = Parser::parseLines($rawInput, SYNC_MAX_PROXIES + 10);
    $toCheck = $parsed['valid'];
    $parseErrors = $parsed['errors'];
    if (count($toCheck) > SYNC_MAX_PROXIES) {
        Http::error('Sync check is limited to ' . SYNC_MAX_PROXIES . ' proxies. Import and create a job instead.', 400);
    }
    if ($toCheck === []) {
        Http::error('No valid proxies provided.', 400, ['parse_errors' => $parseErrors]);
    }
} else {
    Http::error('Provide either ids[] or proxies.', 400);
}

$count = count($toCheck);
if (!Quota::reserve($pdo, $userId, $count)) {
    Http::error('Daily check quota exceeded.', 429, ['quota' => Quota::status($pdo, $userId)]);
}

$results = Checker::checkBatch($toCheck, [
    'timeout' => $timeout,
    'retries' => $retries,
    'plain_http' => $plainHttp,
    'concurrency' => min($count, Config::checkConcurrency()),
]);

$now = Db::nowUtc();
Db::writeTransaction($pdo, static function (PDO $conn) use ($results, $now): void {
    ProxyStore::recordResults($conn, null, $results, $now);
});

Http::json([
    'ok' => true,
    'results' => $results,
    'parse_errors' => $parseErrors,
    'quota' => Quota::status($pdo, $userId),
]);
