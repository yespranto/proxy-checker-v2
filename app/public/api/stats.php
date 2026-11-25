<?php

declare(strict_types=1);

require_once __DIR__ . '/../../auth.php';
require_once __DIR__ . '/../../src/Http.php';
require_once __DIR__ . '/../../src/Quota.php';

Http::requireMethod('GET');
$userId = require_auth_api(false);
$pdo = Db::pdo();

$summaryStmt = $pdo->prepare(
    "SELECT
       COUNT(*) AS total,
       SUM(CASE WHEN status = 'alive' THEN 1 ELSE 0 END) AS alive,
       SUM(CASE WHEN status = 'dead' THEN 1 ELSE 0 END) AS dead,
       SUM(CASE WHEN status = 'unchecked' THEN 1 ELSE 0 END) AS unchecked,
       AVG(CASE WHEN status = 'alive' AND latency_ms IS NOT NULL THEN latency_ms END) AS avg_latency_ms
     FROM proxies
     WHERE user_id = :uid"
);
$summaryStmt->execute([':uid' => $userId]);
$summary = $summaryStmt->fetch() ?: [];

$total = (int) ($summary['total'] ?? 0);
$alive = (int) ($summary['alive'] ?? 0);
$dead = (int) ($summary['dead'] ?? 0);
$unchecked = (int) ($summary['unchecked'] ?? 0);
$checked = $alive + $dead;
$alivePct = $checked > 0 ? round(($alive / $checked) * 100, 1) : 0.0;
$avgLatency = $summary['avg_latency_ms'] !== null ? (int) round((float) $summary['avg_latency_ms']) : null;

$typeStmt = $pdo->prepare(
    "SELECT type, COUNT(*) AS total, SUM(CASE WHEN status = 'alive' THEN 1 ELSE 0 END) AS alive
     FROM proxies WHERE user_id = :uid GROUP BY type ORDER BY total DESC"
);
$typeStmt->execute([':uid' => $userId]);
$byType = array_map(static fn (array $r): array => [
    'type' => (string) $r['type'],
    'total' => (int) $r['total'],
    'alive' => (int) $r['alive'],
], $typeStmt->fetchAll());

$countryStmt = $pdo->prepare(
    "SELECT COALESCE(country_code, '??') AS country_code, COALESCE(country, 'Unknown') AS country, COUNT(*) AS alive
     FROM proxies
     WHERE user_id = :uid AND status = 'alive'
     GROUP BY COALESCE(country_code, '??'), COALESCE(country, 'Unknown')
     ORDER BY alive DESC
     LIMIT 12"
);
$countryStmt->execute([':uid' => $userId]);
$byCountry = array_map(static fn (array $r): array => [
    'country_code' => (string) $r['country_code'],
    'country' => (string) $r['country'],
    'alive' => (int) $r['alive'],
], $countryStmt->fetchAll());

Http::json([
    'ok' => true,
    'totals' => [
        'total' => $total,
        'alive' => $alive,
        'dead' => $dead,
        'unchecked' => $unchecked,
        'alive_pct' => $alivePct,
        'avg_latency_ms' => $avgLatency,
    ],
    'by_type' => $byType,
    'by_country' => $byCountry,
    'quota' => Quota::status($pdo, $userId),
]);
