<?php

declare(strict_types=1);

// Offline unit verification for Parser, Ssrf, Crypto, Db, and Quota.
// Run inside the container or with PHP 8.3: php tests/unit.php

$tmpDb = sys_get_temp_dir() . '/proxychecker_unit_' . bin2hex(random_bytes(4)) . '.db';
putenv('DB_PATH=' . $tmpDb);
putenv('SECRET_KEY=unit-test-secret-key-32-bytes-minimum');
putenv('DAILY_LIMIT=10');

require_once __DIR__ . '/../app/src/Config.php';
require_once __DIR__ . '/../app/src/Db.php';
require_once __DIR__ . '/../app/src/Crypto.php';
require_once __DIR__ . '/../app/src/Quota.php';
require_once __DIR__ . '/../app/src/Parser.php';
require_once __DIR__ . '/../app/src/Ssrf.php';

function assertTrue(bool $cond, string $msg): void
{
    if (!$cond) {
        fwrite(STDERR, "FAIL: {$msg}\n");
        exit(1);
    }
}

try {
    // 1. Parser tests
    $fixture = file_get_contents(__DIR__ . '/fixtures/proxies.txt');
    assertTrue($fixture !== false, 'Read fixture file');
    $parsed = Parser::parseLines($fixture);
    assertTrue(count($parsed['valid']) === 7, 'Expected 7 valid proxies, got ' . count($parsed['valid']));
    assertTrue(count($parsed['errors']) === 4, 'Expected 4 parse errors, got ' . count($parsed['errors']));

    $atPass = $parsed['valid'][1];
    assertTrue($atPass['type'] === 'socks5', 'Type socks5 parsed');
    assertTrue($atPass['username'] === 'user', 'Username parsed');
    assertTrue($atPass['password'] === 'p@ssword', 'Password with @ preserved');
    assertTrue($atPass['host'] === '198.51.100.10', 'Host parsed after last @');

    $colonPass = $parsed['valid'][2];
    assertTrue($colonPass['password'] === 's3cr3t:extra', 'Password with : preserved');

    $v6 = $parsed['valid'][3];
    assertTrue($v6['host'] === '2001:db8::1' && $v6['port'] === 8080 && $v6['type'] === 'http', 'Bracketed IPv6 + trailing type');

    foreach ($parsed['errors'] as $err) {
        assertTrue(!str_contains($err['preview'], 'p@ssword'), 'No password in preview');
    }

    // 2. SSRF tests
    foreach (['127.0.0.1', '10.0.0.1', '172.16.5.4', '192.168.1.1', '169.254.169.254', '::1', '::ffff:127.0.0.1', 'fd00:ec2::254', 'localhost'] as $blocked) {
        $r = Ssrf::resolveAndValidate($blocked);
        assertTrue($r['ok'] === false, "SSRF must block {$blocked}");
    }
    $pub = Ssrf::resolveAndValidate('8.8.8.8');
    assertTrue($pub['ok'] === true && $pub['primary_ip'] === '8.8.8.8', 'Public IP allowed');

    // 3. Crypto tests
    $enc = Crypto::encrypt('p@ssword!');
    assertTrue($enc !== null && $enc !== 'p@ssword!', 'Ciphertext differs from plaintext');
    assertTrue(Crypto::decrypt($enc) === 'p@ssword!', 'Decryption round-trip');
    assertTrue(Crypto::decrypt(null) === null, 'Null decrypts to null');

    // 4. DB + Quota atomic reserve/refund tests
    $pdo = Db::pdo();
    Db::migrate($pdo, __DIR__ . '/../app/migrations');
    $now = Db::nowUtc();
    $pdo->prepare('INSERT INTO users (username, password_hash, role, created_at, updated_at) VALUES (:u,:h,:r,:c,:m)')
        ->execute([':u' => 'u1', ':h' => 'x', ':r' => 'user', ':c' => $now, ':m' => $now]);
    $uid = (int) $pdo->lastInsertId();

    assertTrue(Quota::reserve($pdo, $uid, 6) === true, 'Reserve 6 of 10 succeeds');
    assertTrue(Quota::reserve($pdo, $uid, 5) === false, 'Reserve 5 more exceeds 10 and fails');
    assertTrue(Quota::status($pdo, $uid)['remaining'] === 4, 'Remaining is 4');
    Quota::refund($pdo, $uid, 3);
    assertTrue(Quota::status($pdo, $uid)['remaining'] === 7, 'Remaining is 7 after refund');

    fwrite(STDOUT, "All unit tests passed.\n");
} finally {
    @unlink($tmpDb);
    @unlink($tmpDb . '-wal');
    @unlink($tmpDb . '-shm');
}
