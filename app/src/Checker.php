<?php

declare(strict_types=1);

require_once __DIR__ . '/Config.php';
require_once __DIR__ . '/Ssrf.php';

final class Checker
{
    private const PROXY_TYPE_MAP = [
        'http' => CURLPROXY_HTTP,
        'https' => CURLPROXY_HTTPS,
        'socks4' => CURLPROXY_SOCKS4,
        'socks4a' => CURLPROXY_SOCKS4A,
        'socks5' => CURLPROXY_SOCKS5,
        'socks5h' => CURLPROXY_SOCKS5_HOSTNAME,
    ];

    private const PROXY_HEADERS = [
        'via',
        'x-forwarded-for',
        'forwarded',
        'x-proxy-id',
        'proxy-connection',
        'x-real-ip',
        'client-ip',
        'x-client-ip',
    ];

    /**
     * Check a batch of proxies concurrently via two-stage curl_multi:
     *   Stage 1: Geo/IP probe (with provider rotation & retries)
     *   Stage 1b: Optional anonymity probe via self-hosted echo.php
     *   Stage 2: Risk/detection lookup for unique alive exit IPs
     *
     * @param list<array{
     *   id?: int,
     *   host: string,
     *   port: int,
     *   type: string,
     *   username?: ?string,
     *   password?: ?string
     * }> $proxies
     * @param array{timeout?: int, retries?: int, plain_http?: bool, concurrency?: int} $options
     * @return list<array<string, mixed>> Indexed identically to $proxies
     */
    public static function checkBatch(array $proxies, array $options = []): array
    {
        if ($proxies === []) {
            return [];
        }

        $timeout = max(3, min(30, (int) ($options['timeout'] ?? Config::checkTimeout())));
        $retries = max(0, min(2, (int) ($options['retries'] ?? Config::checkRetries())));
        $concurrency = max(1, min(200, (int) ($options['concurrency'] ?? Config::checkConcurrency())));
        $plainHttp = (bool) ($options['plain_http'] ?? false);

        $providers = Config::ipProviders();
        if ($plainHttp) {
            // Prefer http:// providers first when plain_http is requested
            usort($providers, static function (array $a, array $b): int {
                $aHttp = str_starts_with(strtolower($a['url']), 'http://') ? 0 : 1;
                $bHttp = str_starts_with(strtolower($b['url']), 'http://') ? 0 : 1;
                return $aHttp <=> $bHttp;
            });
        }

        $results = [];
        $stage1Tasks = [];

        foreach ($proxies as $idx => $proxy) {
            $host = (string) $proxy['host'];
            $ssrf = Ssrf::resolveAndValidate($host);
            if (!$ssrf['ok']) {
                $results[$idx] = self::deadResult($proxy, $ssrf['error'], null);
                continue;
            }

            $results[$idx] = self::deadResult($proxy, 'Check did not complete.', null);
            $stage1Tasks[$idx] = [
                'proxy' => $proxy,
                'resolved_ip' => $ssrf['primary_ip'],
                'attempt' => 0,
                'provider_idx' => 0,
            ];
        }

        if ($stage1Tasks !== []) {
            self::runStage1($stage1Tasks, $providers, $timeout, $retries, $concurrency, $results);
        }

        // Collect alive proxies
        $aliveIndices = [];
        $uniqueExitIps = [];
        foreach ($results as $idx => $res) {
            if ($res['alive']) {
                $aliveIndices[] = $idx;
                if (!empty($res['exit_ip'])) {
                    $uniqueExitIps[$res['exit_ip']] = true;
                }
            }
        }

        // Stage 1b: Optional anonymity probe via echo.php
        if ($aliveIndices !== []) {
            self::runAnonymityProbes($proxies, $stage1Tasks, $aliveIndices, $timeout, $concurrency, $results);
        }

        // Stage 2: Risk/detection lookup for alive exit IPs (deduplicated)
        if ($uniqueExitIps !== []) {
            $riskByIp = self::runStage2Risk(array_keys($uniqueExitIps), $timeout, $concurrency);
            foreach ($aliveIndices as $idx) {
                $exitIp = (string) ($results[$idx]['exit_ip'] ?? '');
                if ($exitIp !== '' && isset($riskByIp[$exitIp])) {
                    $risk = $riskByIp[$exitIp];
                    foreach (['isp', 'org', 'asn', 'risk_score', 'is_public_proxy', 'is_blacklisted', 'is_anonymous_vpn', 'user_type'] as $field) {
                        if ($risk[$field] !== null && ($results[$idx][$field] === null || $field === 'risk_score' || str_starts_with($field, 'is_') || $field === 'user_type')) {
                            $results[$idx][$field] = $risk[$field];
                        }
                    }
                }
            }
        }

        ksort($results);
        return array_values($results);
    }

    /**
     * @param array<int, array{proxy: array<string, mixed>, resolved_ip: string, attempt: int, provider_idx: int}> $tasks
     * @param list<array{name: string, url: string, parser: string}> $providers
     * @param array<int, array<string, mixed>> $results
     */
    private static function runStage1(
        array $tasks,
        array $providers,
        int $timeout,
        int $retries,
        int $concurrency,
        array &$results
    ): void {
        if ($providers === []) {
            return;
        }

        $mh = curl_multi_init();
        $queue = array_keys($tasks);
        $activeHandles = []; // spl_object_id(ch) => ['idx' => int, 'ch' => CurlHandle]

        $enqueueNext = static function () use (&$queue, &$tasks, &$activeHandles, $mh, $providers, $timeout): void {
            if ($queue === []) {
                return;
            }
            $idx = array_shift($queue);
            $task = $tasks[$idx];
            $provider = $providers[$task['provider_idx']];
            $ch = self::createProxiedHandle(
                $task['proxy'],
                $task['resolved_ip'],
                $provider['url'],
                $timeout
            );
            curl_multi_add_handle($mh, $ch);
            $activeHandles[spl_object_id($ch)] = ['idx' => $idx, 'ch' => $ch];
        };

        while (count($activeHandles) < $concurrency && $queue !== []) {
            $enqueueNext();
        }

        do {
            $status = curl_multi_exec($mh, $running);
            while ($info = curl_multi_info_read($mh)) {
                if ($info['msg'] !== CURLMSG_DONE) {
                    continue;
                }
                /** @var CurlHandle $ch */
                $ch = $info['handle'];
                $hid = spl_object_id($ch);
                if (!isset($activeHandles[$hid])) {
                    curl_multi_remove_handle($mh, $ch);
                    curl_close($ch);
                    continue;
                }

                $idx = $activeHandles[$hid]['idx'];
                unset($activeHandles[$hid]);

                $task = $tasks[$idx];
                $provider = $providers[$task['provider_idx']];
                $body = curl_multi_getcontent($ch);
                $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $totalTime = (float) curl_getinfo($ch, CURLINFO_TOTAL_TIME);
                $latencyMs = max(1, (int) round($totalTime * 1000));
                $curlErr = curl_error($ch);

                curl_multi_remove_handle($mh, $ch);
                curl_close($ch);

                $parsed = self::parseIpProviderResponse(
                    $provider['parser'],
                    is_string($body) ? $body : '',
                    $httpCode
                );

                if ($parsed !== null) {
                    $results[$idx] = array_merge(
                        self::deadResult($task['proxy'], null, $provider['name']),
                        $parsed,
                        [
                            'alive' => true,
                            'latency_ms' => $latencyMs,
                            'error' => null,
                            'provider' => $provider['name'],
                        ]
                    );
                } else {
                    $errMsg = $curlErr !== ''
                        ? self::sanitizeError($curlErr)
                        : ($httpCode > 0 ? "Provider {$provider['name']} returned HTTP {$httpCode}" : 'Empty or invalid provider response');

                    $nextProvider = $task['provider_idx'] + 1;
                    $nextAttempt = $task['attempt'];

                    if ($nextProvider < count($providers)) {
                        $tasks[$idx]['provider_idx'] = $nextProvider;
                        $queue[] = $idx;
                    } elseif ($nextAttempt < $retries) {
                        $tasks[$idx]['attempt'] = $nextAttempt + 1;
                        $tasks[$idx]['provider_idx'] = 0;
                        $queue[] = $idx;
                    } else {
                        $results[$idx] = self::deadResult($task['proxy'], $errMsg, $provider['name']);
                        $results[$idx]['latency_ms'] = $latencyMs;
                    }
                }

                while (count($activeHandles) < $concurrency && $queue !== []) {
                    $enqueueNext();
                }
            }

            if ($running > 0 || $activeHandles !== []) {
                if ($status === CURLM_OK) {
                    curl_multi_select($mh, 0.2);
                }
            }
        } while ($running > 0 || $activeHandles !== []);

        curl_multi_close($mh);
    }

    /**
     * Run echo.php through alive proxies to classify anonymity.
     *
     * @param list<array<string, mixed>> $proxies
     * @param array<int, array{proxy: array<string, mixed>, resolved_ip: string, attempt: int, provider_idx: int}> $tasks
     * @param list<int> $aliveIndices
     * @param array<int, array<string, mixed>> $results
     */
    private static function runAnonymityProbes(
        array $proxies,
        array $tasks,
        array $aliveIndices,
        int $timeout,
        int $concurrency,
        array &$results
    ): void {
        $echoUrl = Config::echoUrl();
        $echoToken = Config::echoToken();
        if ($echoUrl === '' || $echoToken === '' || !Ssrf::validatePublicUrl($echoUrl)) {
            return;
        }

        $sep = str_contains($echoUrl, '?') ? '&' : '?';
        $targetUrl = $echoUrl . $sep . 't=' . rawurlencode($echoToken);

        $realServerIp = self::fetchDirectServerIp($targetUrl, min(5, $timeout));

        $mh = curl_multi_init();
        $queue = $aliveIndices;
        $activeHandles = [];

        $enqueue = static function () use (&$queue, $proxies, $tasks, &$activeHandles, $mh, $targetUrl, $timeout): void {
            if ($queue === []) {
                return;
            }
            $idx = array_shift($queue);
            $ch = self::createProxiedHandle(
                $proxies[$idx],
                $tasks[$idx]['resolved_ip'],
                $targetUrl,
                $timeout
            );
            curl_multi_add_handle($mh, $ch);
            $activeHandles[spl_object_id($ch)] = ['idx' => $idx, 'ch' => $ch];
        };

        while (count($activeHandles) < $concurrency && $queue !== []) {
            $enqueue();
        }

        do {
            $status = curl_multi_exec($mh, $running);
            while ($info = curl_multi_info_read($mh)) {
                if ($info['msg'] !== CURLMSG_DONE) {
                    continue;
                }
                /** @var CurlHandle $ch */
                $ch = $info['handle'];
                $hid = spl_object_id($ch);
                if (!isset($activeHandles[$hid])) {
                    curl_multi_remove_handle($mh, $ch);
                    curl_close($ch);
                    continue;
                }

                $idx = $activeHandles[$hid]['idx'];
                unset($activeHandles[$hid]);

                $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $body = curl_multi_getcontent($ch);

                curl_multi_remove_handle($mh, $ch);
                curl_close($ch);

                if ($httpCode === 200 && is_string($body)) {
                    $data = json_decode($body, true);
                    if (is_array($data) && isset($data['headers']) && is_array($data['headers'])) {
                        $results[$idx]['anonymity'] = self::classifyAnonymity($data, $realServerIp);
                    }
                }

                while (count($activeHandles) < $concurrency && $queue !== []) {
                    $enqueue();
                }
            }

            if ($running > 0 || $activeHandles !== []) {
                if ($status === CURLM_OK) {
                    curl_multi_select($mh, 0.2);
                }
            }
        } while ($running > 0 || $activeHandles !== []);

        curl_multi_close($mh);
    }

    /**
     * Stage 2: query risk/detection APIs concurrently for unique alive exit IPs.
     *
     * @param list<string> $ips
     * @return array<string, array<string, mixed>>
     */
    private static function runStage2Risk(array $ips, int $timeout, int $concurrency): array
    {
        $providers = Config::riskProviders();
        if ($providers === [] || $ips === []) {
            return [];
        }

        $out = [];
        $tasks = [];
        foreach ($ips as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
                continue;
            }
            $tasks[$ip] = ['ip' => $ip, 'provider_idx' => 0];
            $out[$ip] = [
                'isp' => null,
                'org' => null,
                'asn' => null,
                'risk_score' => null,
                'is_public_proxy' => null,
                'is_blacklisted' => null,
                'is_anonymous_vpn' => null,
                'user_type' => null,
            ];
        }

        $mh = curl_multi_init();
        $queue = array_keys($tasks);
        $active = [];

        $enqueue = static function () use (&$queue, &$tasks, &$active, $mh, $providers, $timeout): void {
            if ($queue === []) {
                return;
            }
            $ip = array_shift($queue);
            $provider = $providers[$tasks[$ip]['provider_idx']];
            $url = str_replace('{ip}', rawurlencode($ip), $provider['url_template']);
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CONNECTTIMEOUT => min(5, $timeout),
                CURLOPT_TIMEOUT => min(8, $timeout),
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_MAXREDIRS => 0,
                (defined('CURLOPT_PROTOCOLS_STR') ? CURLOPT_PROTOCOLS_STR : CURLOPT_PROTOCOLS) => defined('CURLOPT_PROTOCOLS_STR') ? 'http,https' : (CURLPROTO_HTTP | CURLPROTO_HTTPS),
                CURLOPT_USERAGENT => 'ProxyChecker/2.0',
            ]);
            curl_multi_add_handle($mh, $ch);
            $active[spl_object_id($ch)] = ['ip' => $ip, 'ch' => $ch];
        };

        while (count($active) < $concurrency && $queue !== []) {
            $enqueue();
        }

        do {
            $status = curl_multi_exec($mh, $running);
            while ($info = curl_multi_info_read($mh)) {
                if ($info['msg'] !== CURLMSG_DONE) {
                    continue;
                }
                /** @var CurlHandle $ch */
                $ch = $info['handle'];
                $hid = spl_object_id($ch);
                if (!isset($active[$hid])) {
                    curl_multi_remove_handle($mh, $ch);
                    curl_close($ch);
                    continue;
                }

                $ip = $active[$hid]['ip'];
                unset($active[$hid]);

                $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $body = curl_multi_getcontent($ch);
                curl_multi_remove_handle($mh, $ch);
                curl_close($ch);

                $provider = $providers[$tasks[$ip]['provider_idx']];
                $parsed = self::parseRiskResponse(
                    $provider['parser'],
                    is_string($body) ? $body : '',
                    $httpCode
                );

                if ($parsed !== null) {
                    foreach ($parsed as $k => $v) {
                        if ($v !== null) {
                            $out[$ip][$k] = $v;
                        }
                    }
                    // Also try the next risk provider to enrich missing risk_score if first didn't supply it
                    $nextIdx = $tasks[$ip]['provider_idx'] + 1;
                    if ($out[$ip]['risk_score'] === null && $nextIdx < count($providers)) {
                        $tasks[$ip]['provider_idx'] = $nextIdx;
                        $queue[] = $ip;
                    }
                } else {
                    $nextIdx = $tasks[$ip]['provider_idx'] + 1;
                    if ($nextIdx < count($providers)) {
                        $tasks[$ip]['provider_idx'] = $nextIdx;
                        $queue[] = $ip;
                    }
                }

                while (count($active) < $concurrency && $queue !== []) {
                    $enqueue();
                }
            }

            if ($running > 0 || $active !== []) {
                if ($status === CURLM_OK) {
                    curl_multi_select($mh, 0.2);
                }
            }
        } while ($running > 0 || $active !== []);

        curl_multi_close($mh);
        return $out;
    }

    private static function createProxiedHandle(
        array $proxy,
        string $resolvedIp,
        string $url,
        int $timeout
    ): CurlHandle {
        $proxyAddr = str_contains($resolvedIp, ':') ? '[' . $resolvedIp . ']' : $resolvedIp;
        $type = strtolower((string) $proxy['type']);
        $curlProxyType = self::PROXY_TYPE_MAP[$type] ?? CURLPROXY_HTTP;

        $ch = curl_init($url);
        $opts = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_PROXY => $proxyAddr,
            CURLOPT_PROXYPORT => (int) $proxy['port'],
            CURLOPT_PROXYTYPE => $curlProxyType,
            CURLOPT_CONNECTTIMEOUT => min(8, $timeout),
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS => 0,
            (defined('CURLOPT_PROTOCOLS_STR') ? CURLOPT_PROTOCOLS_STR : CURLOPT_PROTOCOLS) => defined('CURLOPT_PROTOCOLS_STR') ? 'http,https' : (CURLPROTO_HTTP | CURLPROTO_HTTPS),
            CURLOPT_USERAGENT => 'Mozilla/5.0 (compatible; ProxyChecker/2.0)',
        ];

        $user = $proxy['username'] ?? null;
        $pass = $proxy['password'] ?? null;
        if ($user !== null && $user !== '') {
            $opts[CURLOPT_PROXYUSERPWD] = $user . ':' . ($pass ?? '');
            $opts[CURLOPT_PROXYAUTH] = CURLAUTH_ANY;
        }

        curl_setopt_array($ch, $opts);
        return $ch;
    }

    private static function parseIpProviderResponse(string $parser, string $body, int $httpCode): ?array
    {
        if ($httpCode !== 200 || $body === '') {
            return null;
        }
        // Reject Cloudflare/HTML challenge pages quickly
        if (str_contains($body, '<html') || str_contains($body, '<!DOCTYPE')) {
            return null;
        }

        $data = json_decode($body, true);
        if (!is_array($data)) {
            return null;
        }

        return match ($parser) {
            'ip_api' => self::parseIpApi($data),
            'ipwhois' => self::parseIpWhois($data),
            'ipify' => self::parseIpify($data),
            default => null,
        };
    }

    private static function parseIpApi(array $d): ?array
    {
        if (($d['status'] ?? '') !== 'success') {
            return null;
        }
        $ip = (string) ($d['query'] ?? '');
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $isProxy = !empty($d['proxy']) ? 1 : 0;
        $isHosting = !empty($d['hosting']) ? 1 : 0;

        return [
            'exit_ip' => $ip,
            'country' => isset($d['country']) ? (string) $d['country'] : null,
            'country_code' => isset($d['countryCode']) ? strtoupper((string) $d['countryCode']) : null,
            'region' => isset($d['regionName']) ? (string) $d['regionName'] : null,
            'city' => isset($d['city']) ? (string) $d['city'] : null,
            'isp' => isset($d['isp']) ? (string) $d['isp'] : null,
            'org' => isset($d['org']) ? (string) $d['org'] : null,
            'asn' => isset($d['as']) ? (string) $d['as'] : null,
            'is_public_proxy' => $isProxy,
            'user_type' => $isHosting ? 'hosting' : 'residential',
        ];
    }

    private static function parseIpWhois(array $d): ?array
    {
        if (isset($d['success']) && $d['success'] === false) {
            return null;
        }
        $ip = (string) ($d['ip'] ?? '');
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }
        $conn = is_array($d['connection'] ?? null) ? $d['connection'] : [];
        return [
            'exit_ip' => $ip,
            'country' => isset($d['country']) ? (string) $d['country'] : null,
            'country_code' => isset($d['country_code']) ? strtoupper((string) $d['country_code']) : null,
            'region' => isset($d['region']) ? (string) $d['region'] : null,
            'city' => isset($d['city']) ? (string) $d['city'] : null,
            'isp' => isset($conn['isp']) ? (string) $conn['isp'] : null,
            'org' => isset($conn['org']) ? (string) $conn['org'] : null,
            'asn' => isset($conn['asn']) ? ('AS' . (string) $conn['asn']) : null,
        ];
    }

    private static function parseIpify(array $d): ?array
    {
        $ip = (string) ($d['ip'] ?? '');
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }
        return ['exit_ip' => $ip];
    }

    private static function parseRiskResponse(string $parser, string $body, int $httpCode): ?array
    {
        if ($httpCode !== 200 || $body === '' || str_contains($body, '<html')) {
            return null;
        }
        $d = json_decode($body, true);
        if (!is_array($d)) {
            return null;
        }

        if ($parser === 'ip_api_risk') {
            if (($d['status'] ?? '') !== 'success') {
                return null;
            }
            $proxy = !empty($d['proxy']) ? 1 : 0;
            $hosting = !empty($d['hosting']) ? 1 : 0;
            $mobile = !empty($d['mobile']) ? 1 : 0;
            $score = ($proxy ? 55 : 0) + ($hosting ? 25 : 0);
            $userType = $mobile ? 'mobile' : ($hosting ? 'hosting' : 'residential');
            return [
                'isp' => isset($d['isp']) ? (string) $d['isp'] : null,
                'org' => isset($d['org']) ? (string) $d['org'] : null,
                'asn' => isset($d['as']) ? (string) $d['as'] : null,
                'risk_score' => $score,
                'is_public_proxy' => $proxy,
                'is_blacklisted' => null,
                'is_anonymous_vpn' => null,
                'user_type' => $userType,
            ];
        }

        if ($parser === 'ipquery') {
            $risk = is_array($d['risk'] ?? null) ? $d['risk'] : [];
            $isp = is_array($d['isp'] ?? null) ? $d['isp'] : [];
            return [
                'isp' => isset($isp['isp']) ? (string) $isp['isp'] : null,
                'org' => isset($isp['org']) ? (string) $isp['org'] : null,
                'asn' => isset($isp['asn']) ? (string) $isp['asn'] : null,
                'risk_score' => isset($risk['risk_score']) ? (int) $risk['risk_score'] : null,
                'is_public_proxy' => isset($risk['is_proxy']) ? ($risk['is_proxy'] ? 1 : 0) : null,
                'is_blacklisted' => isset($risk['is_abuser']) ? ($risk['is_abuser'] ? 1 : 0) : null,
                'is_anonymous_vpn' => isset($risk['is_vpn']) ? ($risk['is_vpn'] ? 1 : 0) : null,
                'user_type' => isset($risk['is_datacenter']) && $risk['is_datacenter'] ? 'hosting' : null,
            ];
        }

        return null;
    }

    private static function fetchDirectServerIp(string $targetUrl, int $timeout): ?string
    {
        $ch = curl_init($targetUrl);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS => 0,
            (defined('CURLOPT_PROTOCOLS_STR') ? CURLOPT_PROTOCOLS_STR : CURLOPT_PROTOCOLS) => defined('CURLOPT_PROTOCOLS_STR') ? 'http,https' : (CURLPROTO_HTTP | CURLPROTO_HTTPS),
        ]);
        $body = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($code !== 200 || !is_string($body)) {
            return null;
        }
        $data = json_decode($body, true);
        if (!is_array($data) || !isset($data['ip']) || !is_string($data['ip'])) {
            return null;
        }
        return filter_var($data['ip'], FILTER_VALIDATE_IP) !== false ? $data['ip'] : null;
    }

    private static function classifyAnonymity(array $echoData, ?string $realServerIp): ?string
    {
        $seenIp = isset($echoData['ip']) && is_string($echoData['ip']) ? $echoData['ip'] : '';
        $headers = [];
        foreach ($echoData['headers'] as $k => $v) {
            if (is_string($k) && is_string($v)) {
                $headers[strtolower($k)] = $v;
            }
        }

        if ($realServerIp !== null && $seenIp === $realServerIp) {
            return 'transparent';
        }

        $hasProxyHeaders = false;
        foreach (self::PROXY_HEADERS as $hdr) {
            if (isset($headers[$hdr]) && trim($headers[$hdr]) !== '') {
                $hasProxyHeaders = true;
                if ($realServerIp !== null && str_contains($headers[$hdr], $realServerIp)) {
                    return 'transparent';
                }
            }
        }

        return $hasProxyHeaders ? 'anonymous' : 'elite';
    }

    private static function deadResult(array $proxy, ?string $error, ?string $provider): array
    {
        return [
            'id' => $proxy['id'] ?? null,
            'host' => (string) $proxy['host'],
            'port' => (int) $proxy['port'],
            'type' => (string) $proxy['type'],
            'has_auth' => !empty($proxy['username']),
            'alive' => false,
            'latency_ms' => null,
            'exit_ip' => null,
            'country' => null,
            'country_code' => null,
            'region' => null,
            'city' => null,
            'isp' => null,
            'org' => null,
            'asn' => null,
            'anonymity' => null,
            'risk_score' => null,
            'is_public_proxy' => null,
            'is_blacklisted' => null,
            'is_anonymous_vpn' => null,
            'user_type' => null,
            'provider' => $provider,
            'error' => $error,
        ];
    }

    private static function sanitizeError(string $err): string
    {
        // Strip any accidental user:pass@ sequences
        $clean = preg_replace('/[^\s:@\/]+:[^\s@\/]+@/', '***:***@', $err) ?? $err;
        if (strlen($clean) > 240) {
            $clean = substr($clean, 0, 237) . '...';
        }
        return $clean;
    }
}
