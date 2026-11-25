<?php

declare(strict_types=1);

final class Parser
{
    public const ALLOWED_TYPES = ['http', 'https', 'socks4', 'socks4a', 'socks5', 'socks5h'];
    public const MAX_IMPORT_LINES = 5000;

    /**
     * Parse multi-line proxy list.
     *
     * @return array{
     *   valid: list<array{host: string, port: int, type: string, username: ?string, password: ?string}>,
     *   errors: list<array{line: int, preview: string, error: string}>,
     *   total_lines: int
     * }
     */
    public static function parseLines(string $input, int $maxLines = self::MAX_IMPORT_LINES): array
    {
        $lines = preg_split('/\r\n|\r|\n/', $input) ?: [];
        if (count($lines) > $maxLines) {
            throw new InvalidArgumentException("Too many lines (max {$maxLines}).");
        }

        $valid = [];
        $errors = [];
        $seen = [];

        foreach ($lines as $idx => $rawLine) {
            $lineNo = $idx + 1;
            $trimmed = trim($rawLine);
            if ($trimmed === '' || str_starts_with($trimmed, '#') || str_starts_with($trimmed, '//')) {
                continue;
            }

            $parsed = self::parseLine($trimmed);
            if (!$parsed['ok']) {
                $errors[] = [
                    'line' => $lineNo,
                    'preview' => self::maskLinePreview($trimmed),
                    'error' => $parsed['error'],
                ];
                continue;
            }

            $p = $parsed['proxy'];
            $dedupKey = strtolower($p['type']) . '|' . strtolower($p['host']) . '|' . $p['port'];
            if (isset($seen[$dedupKey])) {
                continue;
            }
            $seen[$dedupKey] = true;
            $valid[] = $p;
        }

        return [
            'valid' => $valid,
            'errors' => $errors,
            'total_lines' => count($lines),
        ];
    }

    /**
     * Parse a single proxy line.
     * Supports:
     *   - host:port
     *   - host:port:user:pass
     *   - user:pass@host:port
     *   - scheme://[user:pass@]host:port
     *   - optional trailing type word (e.g. `1.2.3.4:8080 socks5`)
     *   - bracketed IPv6 (`[::1]:8080`, `socks5://user:p@ss@[::1]:8080`)
     *
     * @return array{ok: true, proxy: array{host: string, port: int, type: string, username: ?string, password: ?string}}|array{ok: false, error: string}
     */
    public static function parseLine(string $line): array
    {
        $line = trim($line);
        if ($line === '') {
            return ['ok' => false, 'error' => 'Empty line.'];
        }

        // Check for optional trailing type word (separated by whitespace)
        $trailingType = null;
        $parts = preg_split('/\s+/', $line);
        if ($parts !== false && count($parts) > 2) {
            return ['ok' => false, 'error' => 'Unexpected whitespace tokens in proxy line.'];
        }
        if ($parts !== false && count($parts) === 2) {
            $line = $parts[0];
            $trailingType = strtolower(trim($parts[1]));
            if (!in_array($trailingType, self::ALLOWED_TYPES, true)) {
                return ['ok' => false, 'error' => 'Unsupported proxy type: ' . $trailingType];
            }
        }

        // Check for scheme:// prefix
        $schemeType = null;
        if (preg_match('#^([a-zA-Z0-9+.-]+)://(.+)$#', $line, $m)) {
            $scheme = strtolower($m[1]);
            if (!in_array($scheme, self::ALLOWED_TYPES, true)) {
                return ['ok' => false, 'error' => 'Unsupported proxy scheme: ' . $scheme];
            }
            $schemeType = $scheme;
            $line = $m[2];
        }

        if ($schemeType !== null && $trailingType !== null && $schemeType !== $trailingType) {
            return ['ok' => false, 'error' => 'Conflicting proxy scheme and trailing type.'];
        }

        $type = $schemeType ?? $trailingType ?? 'http';

        // Strip trailing slash if someone pasted a URL like http://1.2.3.4:8080/
        $line = rtrim($line, '/');

        $username = null;
        $password = null;
        $hostPort = $line;

        // Split credentials on the LAST '@' so passwords may contain '@'
        $atPos = strrpos($line, '@');
        if ($atPos !== false) {
            $creds = substr($line, 0, $atPos);
            $hostPort = substr($line, $atPos + 1);
            $colonPos = strpos($creds, ':');
            if ($colonPos === false) {
                if ($creds === '') {
                    return ['ok' => false, 'error' => 'Empty credentials before @.'];
                }
                $username = rawurldecode($creds);
                $password = '';
            } else {
                $username = rawurldecode(substr($creds, 0, $colonPos));
                $password = rawurldecode(substr($creds, $colonPos + 1));
            }
        }

        // Parse host + port (with optional :user:pass if '@' wasn't used)
        $host = '';
        $portStr = '';

        if (str_starts_with($hostPort, '[')) {
            if (!preg_match('/^\[([^\]]+)\]:(\d+)(?::(.*))?$/', $hostPort, $m)) {
                return ['ok' => false, 'error' => 'Invalid bracketed IPv6 host:port syntax.'];
            }
            $host = $m[1];
            $portStr = $m[2];
            if (isset($m[3]) && $m[3] !== '') {
                if ($atPos !== false) {
                    return ['ok' => false, 'error' => 'Duplicate credentials specified.'];
                }
                $up = explode(':', $m[3], 2);
                if (count($up) < 2) {
                    return ['ok' => false, 'error' => 'Expected user:pass after host:port.'];
                }
                $username = $up[0];
                $password = $up[1];
            }
        } else {
            $colonCount = substr_count($hostPort, ':');
            if ($colonCount === 0) {
                return ['ok' => false, 'error' => 'Missing port.'];
            }
            if ($colonCount === 1) {
                [$host, $portStr] = explode(':', $hostPort, 2);
            } elseif ($colonCount >= 3 && $atPos === false) {
                // host:port:user:pass (password may contain colons)
                [$host, $portStr, $username, $password] = explode(':', $hostPort, 4);
            } else {
                return ['ok' => false, 'error' => 'Invalid host:port format (wrap IPv6 addresses in brackets [::1]:port).'];
            }
        }

        $host = trim($host);
        if (!self::isValidHost($host)) {
            return ['ok' => false, 'error' => 'Invalid host or IP address.'];
        }

        if (!preg_match('/^\d{1,5}$/', $portStr)) {
            return ['ok' => false, 'error' => 'Invalid port number.'];
        }
        $port = (int) $portStr;
        if ($port < 1 || $port > 65535) {
            return ['ok' => false, 'error' => 'Port must be between 1 and 65535.'];
        }

        if ($username !== null && $username === '' && ($password === null || $password === '')) {
            $username = null;
            $password = null;
        }

        return [
            'ok' => true,
            'proxy' => [
                'host' => strtolower($host),
                'port' => $port,
                'type' => $type,
                'username' => $username,
                'password' => $password,
            ],
        ];
    }

    public static function isValidHost(string $host): bool
    {
        if ($host === '' || strlen($host) > 253) {
            return false;
        }
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return true;
        }
        // Reject whitespace, slashes, or invalid hostname characters
        if (preg_match('/[^a-zA-Z0-9.-]/', $host)) {
            return false;
        }
        return filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false;
    }

    /**
     * Redact potential credentials from an invalid line preview before returning in API/logs.
     */
    public static function maskLinePreview(string $line): string
    {
        $masked = preg_replace('#://([^/@\s]+@)#', '://***:***@', $line) ?? $line;
        if (str_contains($masked, '@')) {
            $pos = strrpos($masked, '@');
            if ($pos !== false) {
                $masked = '***:***@' . substr($masked, $pos + 1);
            }
        } elseif (preg_match('/^([^:\s]+:\d+):.+$/', $masked, $m)) {
            $masked = $m[1] . ':***:***';
        }
        if (strlen($masked) > 80) {
            $masked = substr($masked, 0, 77) . '...';
        }
        return $masked;
    }
}
