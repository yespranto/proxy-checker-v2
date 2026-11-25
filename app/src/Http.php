<?php

declare(strict_types=1);

final class Http
{
    public const MAX_BODY_BYTES = 2_097_152; // 2 MiB

    public static function json(mixed $data, int $status = 200): never
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        exit;
    }

    public static function error(string $message, int $status = 400, array $extra = []): never
    {
        self::json(array_merge(['ok' => false, 'error' => $message], $extra), $status);
    }

    public static function readJsonBody(int $maxBytes = self::MAX_BODY_BYTES): array
    {
        $contentLength = isset($_SERVER['CONTENT_LENGTH']) ? (int) $_SERVER['CONTENT_LENGTH'] : 0;
        if ($contentLength > $maxBytes) {
            self::error('Request body too large.', 413);
        }

        $raw = file_get_contents('php://input', false, null, 0, $maxBytes + 1);
        if ($raw === false) {
            self::error('Failed to read request body.', 400);
        }
        if (strlen($raw) > $maxBytes) {
            self::error('Request body too large.', 413);
        }
        if (trim($raw) === '') {
            return [];
        }

        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            self::error('Invalid JSON payload.', 400);
        }
        return $decoded;
    }

    public static function requireMethod(string ...$methods): string
    {
        $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
        if (!in_array($method, $methods, true)) {
            header('Allow: ' . implode(', ', $methods));
            self::error('Method not allowed.', 405);
        }
        return $method;
    }

    public static function clientIp(): string
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        return filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : '0.0.0.0';
    }
}
