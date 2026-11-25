<?php

declare(strict_types=1);

require_once __DIR__ . '/Db.php';

final class ProxyStore
{
    /**
     * Persist checker results into `proxies` and `checks` inside the caller's connection/transaction.
     *
     * @param list<array<string, mixed>> $results
     */
    public static function recordResults(PDO $conn, ?int $jobId, array $results, string $now): void
    {
        $updProxy = $conn->prepare(
            'UPDATE proxies SET
               status = :status,
               last_checked_at = :checked_at,
               latency_ms = :latency_ms,
               exit_ip = COALESCE(:exit_ip, exit_ip),
               country = COALESCE(:country, country),
               country_code = COALESCE(:country_code, country_code),
               region = COALESCE(:region, region),
               city = COALESCE(:city, city),
               isp = COALESCE(:isp, isp),
               org = COALESCE(:org, org),
               asn = COALESCE(:asn, asn),
               anonymity = COALESCE(:anonymity, anonymity),
               risk_score = COALESCE(:risk_score, risk_score),
               is_public_proxy = COALESCE(:is_public_proxy, is_public_proxy),
               is_blacklisted = COALESCE(:is_blacklisted, is_blacklisted),
               is_anonymous_vpn = COALESCE(:is_anonymous_vpn, is_anonymous_vpn),
               user_type = COALESCE(:user_type, user_type),
               success_count = success_count + :inc_ok,
               fail_count = fail_count + :inc_fail
             WHERE id = :id'
        );

        $insCheck = $conn->prepare(
            'INSERT INTO checks (proxy_id, job_id, checked_at, alive, latency_ms, error, exit_ip, provider)
             VALUES (:pid, :jid, :at, :alive, :lat, :err, :ip, :prov)'
        );

        foreach ($results as $r) {
            if (empty($r['id'])) {
                continue;
            }
            $proxyId = (int) $r['id'];
            $alive = !empty($r['alive']);

            $updProxy->execute([
                ':status' => $alive ? 'alive' : 'dead',
                ':checked_at' => $now,
                ':latency_ms' => $r['latency_ms'],
                ':exit_ip' => $r['exit_ip'],
                ':country' => $r['country'],
                ':country_code' => $r['country_code'],
                ':region' => $r['region'],
                ':city' => $r['city'],
                ':isp' => $r['isp'],
                ':org' => $r['org'],
                ':asn' => $r['asn'],
                ':anonymity' => $r['anonymity'],
                ':risk_score' => $r['risk_score'],
                ':is_public_proxy' => $r['is_public_proxy'],
                ':is_blacklisted' => $r['is_blacklisted'],
                ':is_anonymous_vpn' => $r['is_anonymous_vpn'],
                ':user_type' => $r['user_type'],
                ':inc_ok' => $alive ? 1 : 0,
                ':inc_fail' => $alive ? 0 : 1,
                ':id' => $proxyId,
            ]);

            $insCheck->execute([
                ':pid' => $proxyId,
                ':jid' => $jobId,
                ':at' => $now,
                ':alive' => $alive ? 1 : 0,
                ':lat' => $r['latency_ms'],
                ':err' => $r['error'],
                ':ip' => $r['exit_ip'],
                ':prov' => $r['provider'],
            ]);
        }
    }

    public static function maskRow(array $row): array
    {
        $hasAuth = !empty($row['username']);
        return [
            'id' => (int) $row['id'],
            'host' => (string) $row['host'],
            'port' => (int) $row['port'],
            'type' => (string) $row['type'],
            'has_auth' => $hasAuth,
            'username' => $hasAuth ? self::maskUsername((string) $row['username']) : null,
            'label' => $row['label'],
            'status' => (string) $row['status'],
            'last_checked_at' => $row['last_checked_at'],
            'latency_ms' => $row['latency_ms'] !== null ? (int) $row['latency_ms'] : null,
            'exit_ip' => $row['exit_ip'],
            'country' => $row['country'],
            'country_code' => $row['country_code'],
            'region' => $row['region'],
            'city' => $row['city'],
            'isp' => $row['isp'],
            'org' => $row['org'],
            'asn' => $row['asn'],
            'anonymity' => $row['anonymity'],
            'risk_score' => $row['risk_score'] !== null ? (int) $row['risk_score'] : null,
            'is_public_proxy' => $row['is_public_proxy'] !== null ? (int) $row['is_public_proxy'] : null,
            'is_blacklisted' => $row['is_blacklisted'] !== null ? (int) $row['is_blacklisted'] : null,
            'is_anonymous_vpn' => $row['is_anonymous_vpn'] !== null ? (int) $row['is_anonymous_vpn'] : null,
            'user_type' => $row['user_type'],
            'success_count' => (int) $row['success_count'],
            'fail_count' => (int) $row['fail_count'],
            'created_at' => (string) $row['created_at'],
        ];
    }

    private static function maskUsername(string $u): string
    {
        $len = strlen($u);
        if ($len <= 2) {
            return str_repeat('*', $len);
        }
        return substr($u, 0, 2) . str_repeat('*', min(6, $len - 2));
    }
}
