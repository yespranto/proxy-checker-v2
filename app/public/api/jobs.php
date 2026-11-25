<?php

declare(strict_types=1);

require_once __DIR__ . '/../../auth.php';
require_once __DIR__ . '/../../src/Http.php';
require_once __DIR__ . '/../../src/Quota.php';

const MAX_JOB_PROXIES = 1000;

$method = Http::requireMethod('GET', 'POST');
$userId = require_auth_api(true);
$pdo = Db::pdo();

$action = (string) ($_GET['action'] ?? '');

if ($method === 'GET') {
    if (isset($_GET['id'])) {
        $jobId = (int) $_GET['id'];
        $stmt = $pdo->prepare(
            'SELECT id, status, total, done, alive, dead, timeout_s, retries, created_at, started_at, finished_at
             FROM jobs WHERE id = :id AND user_id = :uid'
        );
        $stmt->execute([':id' => $jobId, ':uid' => $userId]);
        $job = $stmt->fetch();
        if (!$job) {
            Http::error('Job not found.', 404);
        }
        Http::json(['ok' => true, 'job' => formatJob($job)]);
    }

    $stmt = $pdo->prepare(
        'SELECT id, status, total, done, alive, dead, timeout_s, retries, created_at, started_at, finished_at
         FROM jobs WHERE user_id = :uid ORDER BY id DESC LIMIT 20'
    );
    $stmt->execute([':uid' => $userId]);
    $jobs = array_map('formatJob', $stmt->fetchAll());
    Http::json(['ok' => true, 'jobs' => $jobs]);
}

if ($action === 'cancel') {
    $jobId = (int) ($_GET['id'] ?? 0);
    if ($jobId <= 0) {
        Http::error('Missing job id.', 400);
    }

    $result = Db::writeTransaction($pdo, static function (PDO $conn) use ($jobId, $userId): array {
        $stmt = $conn->prepare('SELECT id, status, created_at FROM jobs WHERE id = :id AND user_id = :uid');
        $stmt->execute([':id' => $jobId, ':uid' => $userId]);
        $job = $stmt->fetch();
        if (!$job) {
            return ['not_found' => true];
        }
        if (!in_array($job['status'], ['queued', 'running'], true)) {
            return ['already_terminal' => true, 'status' => $job['status']];
        }

        $cntStmt = $conn->prepare("SELECT COUNT(*) FROM job_items WHERE job_id = :jid AND status = 'pending'");
        $cntStmt->execute([':jid' => $jobId]);
        $pendingCount = (int) $cntStmt->fetchColumn();

        if ($pendingCount > 0) {
            $delStmt = $conn->prepare("DELETE FROM job_items WHERE job_id = :jid AND status = 'pending'");
            $delStmt->execute([':jid' => $jobId]);
            $jobDay = substr((string) $job['created_at'], 0, 10);
            Quota::refund($conn, $userId, $pendingCount, $jobDay);
        }

        $updStmt = $conn->prepare(
            "UPDATE jobs SET status = 'cancelled', finished_at = :now WHERE id = :jid"
        );
        $updStmt->execute([':now' => Db::nowUtc(), ':jid' => $jobId]);

        return ['not_found' => false, 'refunded' => $pendingCount];
    });

    if (!empty($result['not_found'])) {
        Http::error('Job not found.', 404);
    }
    if (!empty($result['already_terminal'])) {
        Http::error('Job is already ' . $result['status'] . '.', 409);
    }

    $stmt = $pdo->prepare(
        'SELECT id, status, total, done, alive, dead, timeout_s, retries, created_at, started_at, finished_at
         FROM jobs WHERE id = :id AND user_id = :uid'
    );
    $stmt->execute([':id' => $jobId, ':uid' => $userId]);
    Http::json([
        'ok' => true,
        'refunded' => $result['refunded'],
        'job' => formatJob($stmt->fetch()),
        'quota' => Quota::status($pdo, $userId),
    ]);
}

// Create a new background check job
$body = Http::readJsonBody();
$timeout = max(3, min(30, (int) ($body['timeout'] ?? Config::checkTimeout())));
$retries = max(0, min(2, (int) ($body['retries'] ?? Config::checkRetries())));

$created = Db::writeTransaction($pdo, static function (PDO $conn) use ($body, $userId, $timeout, $retries): array {
    $proxyIds = [];

    if (!empty($body['all'])) {
        $statusFilter = isset($body['status']) && in_array((string) $body['status'], ['unchecked', 'alive', 'dead'], true)
            ? (string) $body['status']
            : null;
        if ($statusFilter !== null) {
            $stmt = $conn->prepare('SELECT id FROM proxies WHERE user_id = :uid AND status = :st ORDER BY id ASC LIMIT :lim');
            $stmt->bindValue(':uid', $userId, PDO::PARAM_INT);
            $stmt->bindValue(':st', $statusFilter, PDO::PARAM_STR);
            $stmt->bindValue(':lim', MAX_JOB_PROXIES + 1, PDO::PARAM_INT);
            $stmt->execute();
        } else {
            $stmt = $conn->prepare('SELECT id FROM proxies WHERE user_id = :uid ORDER BY id ASC LIMIT :lim');
            $stmt->bindValue(':uid', $userId, PDO::PARAM_INT);
            $stmt->bindValue(':lim', MAX_JOB_PROXIES + 1, PDO::PARAM_INT);
            $stmt->execute();
        }
        $proxyIds = array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN));
    } elseif (isset($body['ids']) && is_array($body['ids'])) {
        $requested = array_values(array_unique(array_filter(array_map('intval', $body['ids']), static fn (int $id): bool => $id > 0)));
        if (count($requested) > MAX_JOB_PROXIES) {
            return ['error' => 'Job exceeds max ' . MAX_JOB_PROXIES . ' proxies.', 'code' => 400];
        }
        if ($requested !== []) {
            $placeholders = implode(',', array_fill(0, count($requested), '?'));
            $stmt = $conn->prepare("SELECT id FROM proxies WHERE user_id = ? AND id IN ({$placeholders}) ORDER BY id ASC");
            $stmt->execute(array_merge([$userId], $requested));
            $proxyIds = array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN));
        }
    } else {
        return ['error' => 'Provide ids[] or all:true.', 'code' => 400];
    }

    if ($proxyIds === []) {
        return ['error' => 'No matching proxies to check.', 'code' => 400];
    }
    if (count($proxyIds) > MAX_JOB_PROXIES) {
        return ['error' => 'Job exceeds max ' . MAX_JOB_PROXIES . ' proxies. Filter or select smaller batches.', 'code' => 400];
    }

    $total = count($proxyIds);
    if (!Quota::reserve($conn, $userId, $total)) {
        return ['error' => 'Daily check quota exceeded.', 'code' => 429];
    }

    $now = Db::nowUtc();
    $insJob = $conn->prepare(
        'INSERT INTO jobs (user_id, status, total, done, alive, dead, timeout_s, retries, created_at)
         VALUES (:uid, \'queued\', :tot, 0, 0, 0, :to, :ret, :at)'
    );
    $insJob->execute([
        ':uid' => $userId,
        ':tot' => $total,
        ':to' => $timeout,
        ':ret' => $retries,
        ':at' => $now,
    ]);
    $jobId = (int) $conn->lastInsertId();

    $insItem = $conn->prepare(
        'INSERT INTO job_items (job_id, proxy_id, status, attempts, lease_until)
         VALUES (:jid, :pid, \'pending\', 0, NULL)'
    );
    foreach ($proxyIds as $pid) {
        $insItem->execute([':jid' => $jobId, ':pid' => $pid]);
    }

    return [
        'ok' => true,
        'job' => [
            'id' => $jobId,
            'status' => 'queued',
            'total' => $total,
            'done' => 0,
            'alive' => 0,
            'dead' => 0,
            'timeout_s' => $timeout,
            'retries' => $retries,
            'created_at' => $now,
            'started_at' => null,
            'finished_at' => null,
        ],
    ];
});

if (empty($created['ok'])) {
    $extra = ($created['code'] ?? 400) === 429 ? ['quota' => Quota::status($pdo, $userId)] : [];
    Http::error((string) $created['error'], (int) ($created['code'] ?? 400), $extra);
}

Http::json([
    'ok' => true,
    'job_id' => $created['job']['id'],
    'job' => $created['job'],
    'quota' => Quota::status($pdo, $userId),
], 201);

function formatJob(array $row): array
{
    return [
        'id' => (int) $row['id'],
        'status' => (string) $row['status'],
        'total' => (int) $row['total'],
        'done' => (int) $row['done'],
        'alive' => (int) $row['alive'],
        'dead' => (int) $row['dead'],
        'timeout_s' => (int) $row['timeout_s'],
        'retries' => (int) $row['retries'],
        'created_at' => (string) $row['created_at'],
        'started_at' => $row['started_at'],
        'finished_at' => $row['finished_at'],
    ];
}
