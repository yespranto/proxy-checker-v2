<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/Config.php';
require_once __DIR__ . '/../src/Db.php';
require_once __DIR__ . '/../src/Crypto.php';
require_once __DIR__ . '/../src/Quota.php';
require_once __DIR__ . '/../src/Checker.php';
require_once __DIR__ . '/../src/ProxyStore.php';

if (PHP_SAPI !== 'cli') {
    exit(1);
}

$running = true;
if (function_exists('pcntl_async_signals')) {
    pcntl_async_signals(true);
    pcntl_signal(SIGTERM, static function () use (&$running): void {
        $running = false;
    });
    pcntl_signal(SIGINT, static function () use (&$running): void {
        $running = false;
    });
}

$pdo = Db::pdo();
$concurrency = Config::checkConcurrency();
fwrite(STDOUT, '[' . Db::nowUtc() . "] Worker started (concurrency={$concurrency}).\n");

while ($running) {
    try {
        runMaintenanceIfDue($pdo);
        $claimed = claimNextBatch($pdo, $concurrency);

        if ($claimed === []) {
            sleep(1);
            continue;
        }

        // Group claimed items by (timeout_s, retries) so each job uses its configured settings
        $groups = [];
        foreach ($claimed as $item) {
            $key = $item['timeout_s'] . ':' . $item['retries'];
            $groups[$key][] = $item;
        }

        foreach ($groups as $groupItems) {
            if (!$running) {
                break;
            }
            $timeout = (int) $groupItems[0]['timeout_s'];
            $retries = (int) $groupItems[0]['retries'];

            $proxiesInput = [];
            foreach ($groupItems as $item) {
                $proxiesInput[] = [
                    'id' => (int) $item['proxy_id'],
                    'host' => (string) $item['host'],
                    'port' => (int) $item['port'],
                    'type' => (string) $item['type'],
                    'username' => $item['username'] !== null ? (string) $item['username'] : null,
                    'password' => Crypto::decrypt($item['password_enc'] !== null ? (string) $item['password_enc'] : null),
                ];
            }

            $results = Checker::checkBatch($proxiesInput, [
                'timeout' => $timeout,
                'retries' => $retries,
                'concurrency' => $concurrency,
            ]);

            persistBatchResults($pdo, $groupItems, $results);
        }
    } catch (Throwable $e) {
        error_log('Worker error: ' . $e->getMessage());
        sleep(2);
    }
}

fwrite(STDOUT, '[' . Db::nowUtc() . "] Worker stopping cleanly.\n");

/**
 * Reclaim expired leases and claim up to $limit pending job items.
 *
 * @return list<array<string, mixed>>
 */
function claimNextBatch(PDO $pdo, int $limit): array
{
    $nowTs = time();
    $nowIso = gmdate('Y-m-d\TH:i:s\Z', $nowTs);

    return Db::writeTransaction($pdo, static function (PDO $conn) use ($limit, $nowTs, $nowIso): array {
        // 1. Reclaim expired leases back to pending
        $reclaim = $conn->prepare(
            "UPDATE job_items
             SET status = 'pending', lease_until = NULL
             WHERE status = 'running' AND lease_until IS NOT NULL AND lease_until < :now"
        );
        $reclaim->execute([':now' => $nowIso]);

        // 2. Clean up any pending items belonging to cancelled/failed jobs
        $conn->exec(
            "DELETE FROM job_items
             WHERE status = 'pending'
               AND job_id IN (SELECT id FROM jobs WHERE status IN ('cancelled', 'failed', 'done'))"
        );

        // 3. Select pending items from active jobs
        $sel = $conn->prepare(
            "SELECT ji.id AS item_id, ji.job_id, ji.proxy_id,
                    j.timeout_s, j.retries, j.user_id,
                    p.host, p.port, p.type, p.username, p.password_enc
             FROM job_items ji
             JOIN jobs j ON j.id = ji.job_id
             JOIN proxies p ON p.id = ji.proxy_id
             WHERE ji.status = 'pending' AND j.status IN ('queued', 'running')
             ORDER BY ji.id ASC
             LIMIT :lim"
        );
        $sel->bindValue(':lim', $limit, PDO::PARAM_INT);
        $sel->execute();
        $rows = $sel->fetchAll();

        if ($rows === []) {
            return [];
        }

        $updItem = $conn->prepare(
            "UPDATE job_items
             SET status = 'running', attempts = attempts + 1, lease_until = :lease
             WHERE id = :id"
        );
        $updJob = $conn->prepare(
            "UPDATE jobs
             SET status = 'running', started_at = COALESCE(started_at, :now)
             WHERE id = :jid AND status = 'queued'"
        );

        $seenJobs = [];
        foreach ($rows as $r) {
            $leaseSec = ((int) $r['timeout_s'] * ((int) $r['retries'] + 1)) + 30;
            $leaseIso = gmdate('Y-m-d\TH:i:s\Z', $nowTs + $leaseSec);
            $updItem->execute([':lease' => $leaseIso, ':id' => (int) $r['item_id']]);

            $jid = (int) $r['job_id'];
            if (!isset($seenJobs[$jid])) {
                $seenJobs[$jid] = true;
                $updJob->execute([':now' => $nowIso, ':jid' => $jid]);
            }
        }

        return $rows;
    });
}

/**
 * Write check results, advance job counters, handle cancellation refunds, and mark finished jobs done.
 *
 * @param list<array<string, mixed>> $items
 * @param list<array<string, mixed>> $results
 */
function persistBatchResults(PDO $pdo, array $items, array $results): void
{
    $now = Db::nowUtc();

    Db::writeTransaction($pdo, static function (PDO $conn) use ($items, $results, $now): void {
        $jobIds = array_values(array_unique(array_map(static fn (array $r): int => (int) $r['job_id'], $items)));
        $placeholders = implode(',', array_fill(0, count($jobIds), '?'));
        $jobStmt = $conn->prepare("SELECT id, user_id, status, created_at FROM jobs WHERE id IN ({$placeholders})");
        $jobStmt->execute($jobIds);
        $jobsById = [];
        foreach ($jobStmt->fetchAll() as $j) {
            $jobsById[(int) $j['id']] = $j;
        }

        $markItemDone = $conn->prepare("UPDATE job_items SET status = 'done', lease_until = NULL WHERE id = :id");
        $incJob = $conn->prepare(
            'UPDATE jobs SET done = done + :d, alive = alive + :a, dead = dead + :dead WHERE id = :jid'
        );

        $toRecordByJob = [];
        $jobDeltas = [];
        $refunds = [];

        foreach ($items as $idx => $item) {
            $itemId = (int) $item['item_id'];
            $jobId = (int) $item['job_id'];
            $job = $jobsById[$jobId] ?? null;

            $markItemDone->execute([':id' => $itemId]);

            if ($job === null || $job['status'] === 'cancelled') {
                if ($job !== null) {
                    $key = $job['user_id'] . '|' . substr((string) $job['created_at'], 0, 10);
                    $refunds[$key] = ($refunds[$key] ?? 0) + 1;
                }
                continue;
            }

            $res = $results[$idx] ?? null;
            if ($res === null) {
                continue;
            }

            $toRecordByJob[$jobId][] = $res;
            if (!isset($jobDeltas[$jobId])) {
                $jobDeltas[$jobId] = ['done' => 0, 'alive' => 0, 'dead' => 0];
            }
            $jobDeltas[$jobId]['done']++;
            if (!empty($res['alive'])) {
                $jobDeltas[$jobId]['alive']++;
            } else {
                $jobDeltas[$jobId]['dead']++;
            }
        }

        foreach ($toRecordByJob as $jid => $jobResults) {
            ProxyStore::recordResults($conn, $jid, $jobResults, $now);
        }

        foreach ($jobDeltas as $jid => $delta) {
            $incJob->execute([
                ':d' => $delta['done'],
                ':a' => $delta['alive'],
                ':dead' => $delta['dead'],
                ':jid' => $jid,
            ]);
        }

        foreach ($refunds as $key => $count) {
            [$uid, $day] = explode('|', $key, 2);
            Quota::refund($conn, (int) $uid, $count, $day);
        }

        // Mark jobs done if no pending or running items remain
        $remStmt = $conn->prepare("SELECT COUNT(*) FROM job_items WHERE job_id = :jid AND status != 'done'");
        $doneStmt = $conn->prepare("UPDATE jobs SET status = 'done', finished_at = :now WHERE id = :jid AND status IN ('queued', 'running')");
        foreach ($jobIds as $jid) {
            $remStmt->execute([':jid' => $jid]);
            if ((int) $remStmt->fetchColumn() === 0) {
                $doneStmt->execute([':now' => $now, ':jid' => $jid]);
            }
        }
    });
}

/**
 * Once per UTC day: prune checks older than 30 days and create a SQLite backup (keeping last 7).
 */
function runMaintenanceIfDue(PDO $pdo): void
{
    $today = gmdate('Ymd');
    $stmt = $pdo->prepare("SELECT value FROM settings WHERE key = 'last_maintenance_day'");
    $stmt->execute();
    if ($stmt->fetchColumn() === $today) {
        return;
    }

    // Prune checks older than 30 days
    $cutoff = gmdate('Y-m-d\TH:i:s\Z', time() - (30 * 86400));
    Db::writeTransaction($pdo, static function (PDO $conn) use ($cutoff, $today): void {
        $del = $conn->prepare('DELETE FROM checks WHERE checked_at < :cutoff');
        $del->execute([':cutoff' => $cutoff]);

        $upd = $conn->prepare(
            "INSERT INTO settings (key, value) VALUES ('last_maintenance_day', :d)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value"
        );
        $upd->execute([':d' => $today]);
    });

    // Online SQLite backup via VACUUM INTO (works with disable_functions enabled)
    try {
        $backupDir = dirname(Config::dbPath()) . '/backups';
        if (is_dir($backupDir) || @mkdir($backupDir, 0770, true)) {
            $backupFile = $backupDir . '/app-' . $today . '.db';
            if (!file_exists($backupFile)) {
                $quoted = $pdo->quote($backupFile);
                $pdo->exec("VACUUM INTO {$quoted}");
            }

            $files = glob($backupDir . '/app-*.db') ?: [];
            sort($files, SORT_STRING);
            while (count($files) > 7) {
                $oldest = array_shift($files);
                if ($oldest !== null) {
                    @unlink($oldest);
                }
            }
        }
    } catch (Throwable $e) {
        error_log('Nightly backup failed: ' . $e->getMessage());
    }
}
