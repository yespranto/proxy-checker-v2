<?php

declare(strict_types=1);

final class Config
{
    public static function dbPath(): string
    {
        $v = getenv('DB_PATH');
        return ($v !== false && $v !== '') ? $v : '/data/app.db';
    }

    public static function appEnv(): string
    {
        $v = getenv('APP_ENV');
        return ($v !== false && $v !== '') ? $v : 'production';
    }

    public static function secretKey(): string
    {
        $v = getenv('SECRET_KEY');
        if ($v === false || trim($v) === '') {
            throw new RuntimeException('SECRET_KEY environment variable is required.');
        }
        return $v;
    }

    public static function adminUser(): string
    {
        $v = getenv('ADMIN_USER');
        return $v !== false ? trim($v) : '';
    }

    public static function adminPassword(): string
    {
        $v = getenv('ADMIN_PASSWORD');
        return $v !== false ? $v : '';
    }

    public static function dailyLimit(): int
    {
        $v = (int) (getenv('DAILY_LIMIT') ?: 500);
        return max(1, $v);
    }

    public static function checkConcurrency(): int
    {
        $v = (int) (getenv('CHECK_CONCURRENCY') ?: 40);
        return max(1, min(200, $v));
    }

    public static function checkTimeout(): int
    {
        $v = (int) (getenv('CHECK_TIMEOUT') ?: 12);
        return max(3, min(30, $v));
    }

    public static function checkRetries(): int
    {
        $v = (int) (getenv('CHECK_RETRIES') ?: 1);
        return max(0, min(2, $v));
    }

    public static function echoToken(): string
    {
        $v = getenv('ECHO_TOKEN');
        return $v !== false ? trim($v) : '';
    }

    public static function echoUrl(): string
    {
        $v = getenv('ECHO_URL');
        return $v !== false ? trim($v) : '';
    }

    /**
     * Configurable geo/IP providers. Each entry defines a name, URL, and response parser key.
     *
     * @return list<array{name: string, url: string, parser: string}>
     */
    public static function ipProviders(): array
    {
        $custom = getenv('IP_PROVIDERS_JSON');
        if ($custom !== false && trim($custom) !== '') {
            $decoded = json_decode($custom, true);
            if (is_array($decoded) && $decoded !== []) {
                return array_values($decoded);
            }
        }

        return [
            [
                'name' => 'ip-api',
                'url' => 'http://ip-api.com/json/?fields=status,message,country,countryCode,regionName,city,isp,org,as,proxy,hosting,query',
                'parser' => 'ip_api',
            ],
            [
                'name' => 'ipwho.is',
                'url' => 'https://ipwho.is/',
                'parser' => 'ipwhois',
            ],
            [
                'name' => 'ipify',
                'url' => 'https://api.ipify.org?format=json',
                'parser' => 'ipify',
            ],
        ];
    }

    /**
     * Configurable risk/detection providers (run in Stage 2 only for alive exit IPs).
     *
     * @return list<array{name: string, url_template: string, parser: string}>
     */
    public static function riskProviders(): array
    {
        return [
            [
                'name' => 'ip-api-risk',
                'url_template' => 'http://ip-api.com/json/{ip}?fields=status,proxy,hosting,mobile,isp,org,as',
                'parser' => 'ip_api_risk',
            ],
            [
                'name' => 'ipquery',
                'url_template' => 'https://api.ipquery.io/{ip}',
                'parser' => 'ipquery',
            ],
        ];
    }
}
