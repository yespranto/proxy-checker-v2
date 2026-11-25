<?php

declare(strict_types=1);

require_once __DIR__ . '/../../auth.php';
require_once __DIR__ . '/../../src/Http.php';
require_once __DIR__ . '/../../src/Parser.php';
require_once __DIR__ . '/../../src/Crypto.php';
require_once __DIR__ . '/../../src/ProxyStore.php';

$method = Http::requireMethod('GET', 'POST', 'DELETE');
$userId = require_auth_api(true);
$pdo = Db::pdo();

$action = (string) ($_GET['action'] ?? '');

if ($method === 'POST' && $action === 'import') {
    handleImport($pdo, $userId);
}

if ($method === 'GET' && $action === 'export') {
    handleExport($pdo, $userId);
}

if ($method === 'GET') {
    handleList($pdo, $userId);
}

if ($method === 'DELETE') {
    handleDelete($pdo, $userId);
}

Http::error('Invalid request.', 400);

function handleImport(PDO $pdo, int $userId): never
{
    $rawText = '';
    $label = null;

    $contentType = strtolower((string) ($_SERVER['CONTENT_TYPE'] ?? ''));
    if (str_contains($contentType, 'multipart/form-data')) {
        if (!empty($_FILES['file']['tmp_name']) && is_uploaded_file($_FILES['file']['tmp_name'])) {
            $size = (int) ($_FILES['file']['size'] ?? 0);
            if ($size > Http::MAX_BODY_BYTES) {
                Http::error('Uploaded file exceeds size limit.', 413);
            }
            $rawText = (string) file_get_contents($_FILES['file']['tmp_name']);
        } else {
            $rawText = (string) ($_POST['text'] ?? '');
        }
        $label = isset($_POST['label']) && trim((string) $_POST['label']) !== ''
            ? substr(trim((string) $_POST['label']), 0, 64)
            : null;
    } else {
        $body = Http::readJsonBody();
        $rawText = (string) ($body['text'] ?? ($body['proxies'] ?? ''));
        $label = isset($body['label']) && trim((string) $body['label']) !== ''
            ? substr(trim((string) $body['label']), 0, 64)
            : null;
    }

    if (trim($rawText) === '') {
        Http::error('No proxy lines provided.', 400);
    }

    try {
        $parsed = Parser::parseLines($rawText, Parser::MAX_IMPORT_LINES);
    } catch (InvalidArgumentException $e) {
        Http::error($e->getMessage(), 400);
    }

    $valid = $parsed['valid'];
    $errors = $parsed['errors'];
    $now = Db::nowUtc();

    $stats = Db::writeTransaction($pdo, static function (PDO $conn) use ($valid, $userId, $label, $now): array {
        $checkStmt = $conn->prepare(
            'SELECT id FROM proxies WHERE user_id = :uid AND host = :host AND port = :port AND type = :type'
        );
        $insStmt = $conn->prepare(
            'INSERT INTO proxies (user_id, host, port, type, username, password_enc, label, created_at)
             VALUES (:uid, :host, :port, :type, :user, :pass_enc, :label, :at)'
        );
        $updStmt = $conn->prepare(
            'UPDATE proxies SET
               username = :user,
               password_enc = :pass_enc,
               label = COALESCE(:label, label)
             WHERE id = :id'
        );

        $inserted = 0;
        $updated = 0;
        $ids = [];

        foreach ($valid as $p) {
            $checkStmt->execute([
                ':uid' => $userId,
                ':host' => $p['host'],
                ':port' => $p['port'],
                ':type' => $p['type'],
            ]);
            $existingId = $checkStmt->fetchColumn();
            $passEnc = Crypto::encrypt($p['password']);

            if ($existingId !== false) {
                $updStmt->bindValue(':user', $p['username'], $p['username'] === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
                $updStmt->bindValue(':pass_enc', $passEnc, $passEnc === null ? PDO::PARAM_NULL : PDO::PARAM_LOB);
                $updStmt->bindValue(':label', $label, $label === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
                $updStmt->bindValue(':id', (int) $existingId, PDO::PARAM_INT);
                $updStmt->execute();
                $updated++;
                $ids[] = (int) $existingId;
            } else {
                $insStmt->bindValue(':uid', $userId, PDO::PARAM_INT);
                $insStmt->bindValue(':host', $p['host'], PDO::PARAM_STR);
                $insStmt->bindValue(':port', $p['port'], PDO::PARAM_INT);
                $insStmt->bindValue(':type', $p['type'], PDO::PARAM_STR);
                $insStmt->bindValue(':user', $p['username'], $p['username'] === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
                $insStmt->bindValue(':pass_enc', $passEnc, $passEnc === null ? PDO::PARAM_NULL : PDO::PARAM_LOB);
                $insStmt->bindValue(':label', $label, $label === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
                $insStmt->bindValue(':at', $now, PDO::PARAM_STR);
                $insStmt->execute();
                $inserted++;
                $ids[] = (int) $conn->lastInsertId();
            }
        }

        return ['inserted' => $inserted, 'updated' => $updated, 'ids' => $ids];
    });

    Http::json([
        'ok' => true,
        'inserted' => $stats['inserted'],
        'updated' => $stats['updated'],
        'total_valid' => count($valid),
        'ids' => $stats['ids'],
        'errors' => $errors,
    ]);
}

function buildFilterClause(int $userId, array $query, array &$params): string
{
    $where = ['user_id = :uid'];
    $params[':uid'] = $userId;

    $status = trim((string) ($query['status'] ?? ''));
    if (in_array($status, ['unchecked', 'alive', 'dead'], true)) {
        $where[] = 'status = :status';
        $params[':status'] = $status;
    }

    $type = strtolower(trim((string) ($query['type'] ?? '')));
    if (in_array($type, Parser::ALLOWED_TYPES, true)) {
        $where[] = 'type = :type';
        $params[':type'] = $type;
    }

    $country = strtoupper(trim((string) ($query['country'] ?? '')));
    if ($country !== '') {
        if (strlen($country) === 2) {
            $where[] = 'UPPER(country_code) = :cc';
            $params[':cc'] = $country;
        } else {
            $where[] = 'UPPER(country) = :cname';
            $params[':cname'] = $country;
        }
    }

    $maxLatency = isset($query['max_latency']) && $query['max_latency'] !== '' ? (int) $query['max_latency'] : 0;
    if ($maxLatency > 0) {
        $where[] = 'latency_ms IS NOT NULL AND latency_ms <= :max_lat';
        $params[':max_lat'] = $maxLatency;
    }

    $q = trim((string) ($query['q'] ?? ''));
    if ($q !== '') {
        $where[] = '(host LIKE :q OR exit_ip LIKE :q OR country LIKE :q OR isp LIKE :q OR org LIKE :q OR label LIKE :q)';
        $params[':q'] = '%' . $q . '%';
    }

    return implode(' AND ', $where);
}

function handleList(PDO $pdo, int $userId): never
{
    $params = [];
    $whereSql = buildFilterClause($userId, $_GET, $params);

    $sortMap = [
        'id' => 'id',
        'host' => 'host',
        'port' => 'port',
        'type' => 'type',
        'status' => 'status',
        'latency_ms' => 'COALESCE(latency_ms, 9999999)',
        'country_code' => 'COALESCE(country_code, "ZZ")',
        'anonymity' => 'COALESCE(anonymity, "zzz")',
        'risk_score' => 'COALESCE(risk_score, 999)',
        'last_checked_at' => 'COALESCE(last_checked_at, "")',
        'created_at' => 'created_at',
    ];
    $sortKey = (string) ($_GET['sort'] ?? 'id');
    $orderExpr = $sortMap[$sortKey] ?? 'id';
    $dir = strtoupper((string) ($_GET['dir'] ?? 'DESC')) === 'ASC' ? 'ASC' : 'DESC';

    $page = max(1, (int) ($_GET['page'] ?? 1));
    $perPage = max(1, min(200, (int) ($_GET['per_page'] ?? 50)));
    $offset = ($page - 1) * $perPage;

    $countStmt = $pdo->prepare("SELECT COUNT(*) FROM proxies WHERE {$whereSql}");
    $countStmt->execute($params);
    $total = (int) $countStmt->fetchColumn();

    $sql = "SELECT id, host, port, type, username, label, status, last_checked_at, latency_ms,
                   exit_ip, country, country_code, region, city, isp, org, asn, anonymity,
                   risk_score, is_public_proxy, is_blacklisted, is_anonymous_vpn, user_type,
                   success_count, fail_count, created_at
            FROM proxies
            WHERE {$whereSql}
            ORDER BY {$orderExpr} {$dir}, id DESC
            LIMIT :lim OFFSET :off";

    $stmt = $pdo->prepare($sql);
    foreach ($params as $k => $v) {
        $stmt->bindValue($k, $v);
    }
    $stmt->bindValue(':lim', $perPage, PDO::PARAM_INT);
    $stmt->bindValue(':off', $offset, PDO::PARAM_INT);
    $stmt->execute();

    $items = array_map([ProxyStore::class, 'maskRow'], $stmt->fetchAll());

    Http::json([
        'ok' => true,
        'items' => $items,
        'total' => $total,
        'page' => $page,
        'per_page' => $perPage,
        'pages' => max(1, (int) ceil($total / $perPage)),
    ]);
}

function handleDelete(PDO $pdo, int $userId): never
{
    $body = Http::readJsonBody();
    $deleted = 0;

    if (isset($body['ids']) && is_array($body['ids'])) {
        $ids = array_values(array_unique(array_filter(array_map('intval', $body['ids']), static fn (int $id): bool => $id > 0)));
        if ($ids === []) {
            Http::error('No valid IDs provided.', 400);
        }
        $deleted = Db::writeTransaction($pdo, static function (PDO $conn) use ($userId, $ids): int {
            $placeholders = implode(',', array_fill(0, count($ids), '?'));
            $stmt = $conn->prepare("DELETE FROM proxies WHERE user_id = ? AND id IN ({$placeholders})");
            $stmt->execute(array_merge([$userId], $ids));
            return $stmt->rowCount();
        });
    } elseif (isset($body['status']) && in_array((string) $body['status'], ['dead', 'unchecked', 'alive'], true)) {
        $status = (string) $body['status'];
        $deleted = Db::writeTransaction($pdo, static function (PDO $conn) use ($userId, $status): int {
            $stmt = $conn->prepare('DELETE FROM proxies WHERE user_id = :uid AND status = :status');
            $stmt->execute([':uid' => $userId, ':status' => $status]);
            return $stmt->rowCount();
        });
    } else {
        Http::error('Specify ids[] or status to delete.', 400);
    }

    Http::json(['ok' => true, 'deleted' => $deleted]);
}

function handleExport(PDO $pdo, int $userId): never
{
    $format = strtolower((string) ($_GET['format'] ?? 'txt'));
    if (!in_array($format, ['txt', 'csv'], true)) {
        Http::error('Unsupported export format. Use txt or csv.', 400);
    }

    $params = [];
    $whereSql = buildFilterClause($userId, $_GET, $params);
    $stmt = $pdo->prepare(
        "SELECT id, host, port, type, status, latency_ms, exit_ip, country_code, country, isp, anonymity, risk_score, last_checked_at
         FROM proxies
         WHERE {$whereSql}
         ORDER BY COALESCE(latency_ms, 9999999) ASC, id ASC"
    );
    $stmt->execute($params);
    $rows = $stmt->fetchAll();

    header('Cache-Control: no-store');

    if ($format === 'txt') {
        header('Content-Type: text/plain; charset=utf-8');
        header('Content-Disposition: attachment; filename="proxies-' . gmdate('Ymd-His') . '.txt"');
        foreach ($rows as $r) {
            $host = str_contains((string) $r['host'], ':') ? '[' . $r['host'] . ']' : $r['host'];
            echo $r['type'] . '://' . $host . ':' . $r['port'] . "\n";
        }
        exit;
    }

    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="proxies-' . gmdate('Ymd-His') . '.csv"');
    $out = fopen('php://output', 'wb');
    fputcsv($out, ['id', 'host', 'port', 'type', 'status', 'latency_ms', 'exit_ip', 'country_code', 'country', 'isp', 'anonymity', 'risk_score', 'last_checked_at']);
    foreach ($rows as $r) {
        fputcsv($out, [
            $r['id'],
            csvSafe((string) $r['host']),
            $r['port'],
            $r['type'],
            $r['status'],
            $r['latency_ms'],
            csvSafe((string) ($r['exit_ip'] ?? '')),
            csvSafe((string) ($r['country_code'] ?? '')),
            csvSafe((string) ($r['country'] ?? '')),
            csvSafe((string) ($r['isp'] ?? '')),
            $r['anonymity'],
            $r['risk_score'],
            $r['last_checked_at'],
        ]);
    }
    fclose($out);
    exit;
}

function csvSafe(string $val): string
{
    if ($val !== '' && in_array($val[0], ['=', '+', '-', '@', "\t", "\r"], true)) {
        return "'" . $val;
    }
    return $val;
}
