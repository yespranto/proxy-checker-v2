<?php

declare(strict_types=1);

final class Ssrf
{
    public const BLOCKED_ERROR = 'Proxy host resolves to a restricted or unreachable address.';

    /**
     * Resolve $host and verify ALL resolved IPs are public unicast addresses.
     * Returns ['ok' => true, 'primary_ip' => string, 'ips' => list<string>]
     * or      ['ok' => false, 'error' => string].
     *
     * @return array{ok: true, primary_ip: string, ips: list<string>}|array{ok: false, error: string}
     */
    public static function resolveAndValidate(string $host): array
    {
        $host = trim($host, " \t\n\r\0\x0B[]");
        if ($host === '') {
            return ['ok' => false, 'error' => self::BLOCKED_ERROR];
        }

        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            if (!self::isPublicIp($host)) {
                return ['ok' => false, 'error' => self::BLOCKED_ERROR];
            }
            return ['ok' => true, 'primary_ip' => $host, 'ips' => [$host]];
        }

        $lower = strtolower($host);
        if (
            $lower === 'localhost'
            || str_ends_with($lower, '.localhost')
            || str_ends_with($lower, '.local')
            || str_ends_with($lower, '.internal')
            || str_ends_with($lower, '.arpa')
        ) {
            return ['ok' => false, 'error' => self::BLOCKED_ERROR];
        }

        $ips = self::resolveHost($host);
        if ($ips === []) {
            return ['ok' => false, 'error' => self::BLOCKED_ERROR];
        }

        foreach ($ips as $ip) {
            if (!self::isPublicIp($ip)) {
                return ['ok' => false, 'error' => self::BLOCKED_ERROR];
            }
        }

        return ['ok' => true, 'primary_ip' => $ips[0], 'ips' => $ips];
    }

    /**
     * @return list<string>
     */
    private static function resolveHost(string $host): array
    {
        $ips = [];
        $records = @dns_get_record($host, DNS_A | DNS_AAAA);
        if (is_array($records)) {
            foreach ($records as $rec) {
                if (isset($rec['ip']) && is_string($rec['ip'])) {
                    $ips[] = $rec['ip'];
                } elseif (isset($rec['ipv6']) && is_string($rec['ipv6'])) {
                    $ips[] = $rec['ipv6'];
                }
            }
        }

        if ($ips === []) {
            $v4 = @gethostbynamel($host);
            if (is_array($v4)) {
                foreach ($v4 as $ip) {
                    $ips[] = $ip;
                }
            }
        }

        return array_values(array_unique($ips));
    }

    public static function isPublicIp(string $ip): bool
    {
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return false;
        }

        if (strlen($packed) === 4) {
            return self::isPublicIpv4Bytes($packed);
        }

        if (strlen($packed) === 16) {
            return self::isPublicIpv6Bytes($packed);
        }

        return false;
    }

    private static function isPublicIpv4Bytes(string $bytes): bool
    {
        $n = unpack('N', $bytes)[1];
        // Convert signed/unsigned 32-bit int safely on 64-bit PHP
        $u = $n & 0xFFFFFFFF;

        $blockedCidrs = [
            [0x00000000, 0xFF000000], // 0.0.0.0/8
            [0x0A000000, 0xFF000000], // 10.0.0.0/8
            [0x64400000, 0xFFC00000], // 100.64.0.0/10 (CGNAT)
            [0x7F000000, 0xFF000000], // 127.0.0.0/8 (loopback)
            [0xA9FE0000, 0xFFFF0000], // 169.254.0.0/16 (link-local & cloud metadata)
            [0xAC100000, 0xFFF00000], // 172.16.0.0/12
            [0xC0000000, 0xFFFFFF00], // 192.0.0.0/24
            [0xC0000200, 0xFFFFFF00], // 192.0.2.0/24
            [0xC0586300, 0xFFFFFF00], // 192.88.99.0/24
            [0xC0A80000, 0xFFFF0000], // 192.168.0.0/16
            [0xC6120000, 0xFFFE0000], // 198.18.0.0/15
            [0xC6336400, 0xFFFFFF00], // 198.51.100.0/24
            [0xCB007100, 0xFFFFFF00], // 203.0.113.0/24
            [0xE0000000, 0xF0000000], // 224.0.0.0/4 (multicast)
            [0xF0000000, 0xF0000000], // 240.0.0.0/4 (reserved + broadcast)
        ];

        foreach ($blockedCidrs as [$net, $mask]) {
            if (($u & $mask) === $net) {
                return false;
            }
        }

        return true;
    }

    private static function isPublicIpv6Bytes(string $bytes): bool
    {
        // Unspecified ::/128
        if ($bytes === str_repeat("\x00", 16)) {
            return false;
        }
        // Loopback ::1/128
        if ($bytes === str_repeat("\x00", 15) . "\x01") {
            return false;
        }
        // IPv4-mapped ::ffff:0:0/96 or IPv4-compatible ::/96 -> inspect last 4 bytes
        if (substr($bytes, 0, 12) === str_repeat("\x00", 10) . "\xff\xff"
            || substr($bytes, 0, 12) === str_repeat("\x00", 12)) {
            return self::isPublicIpv4Bytes(substr($bytes, 12, 4));
        }
        // NAT64 64:ff9b::/96 -> inspect embedded IPv4
        if (substr($bytes, 0, 12) === "\x00\x64\xff\x9b" . str_repeat("\x00", 8)) {
            return self::isPublicIpv4Bytes(substr($bytes, 12, 4));
        }
        // 100::/64 discard prefix
        if (substr($bytes, 0, 8) === "\x01\x00" . str_repeat("\x00", 6)) {
            return false;
        }
        // 2001:db8::/32 documentation & 2001:2::/48 benchmarking & 2001::/32 Teredo
        $first4 = substr($bytes, 0, 4);
        if ($first4 === "\x20\x01\x0d\xb8" || $first4 === "\x20\x01\x00\x00") {
            return false;
        }
        if (substr($bytes, 0, 6) === "\x20\x01\x00\x02\x00\x00") {
            return false;
        }

        $b0 = ord($bytes[0]);
        $b1 = ord($bytes[1]);

        // fc00::/7 unique local (includes fd00::/8 and cloud metadata fd00:ec2::254)
        if (($b0 & 0xFE) === 0xFC) {
            return false;
        }
        // fe80::/10 link-local
        if ($b0 === 0xFE && ($b1 & 0xC0) === 0x80) {
            return false;
        }
        // ff00::/8 multicast
        if ($b0 === 0xFF) {
            return false;
        }

        return true;
    }

    /**
     * Validate a target URL (such as ECHO_URL) so it points to a public HTTP(S) host.
     */
    public static function validatePublicUrl(string $url): bool
    {
        $parts = parse_url($url);
        if (!is_array($parts)) {
            return false;
        }
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = (string) ($parts['host'] ?? '');
        if (!in_array($scheme, ['http', 'https'], true) || $host === '') {
            return false;
        }
        $res = self::resolveAndValidate($host);
        return $res['ok'];
    }
}
