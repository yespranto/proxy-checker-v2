<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/Config.php';
require_once __DIR__ . '/../src/Db.php';

$pdo = Db::pdo();
$applied = Db::migrate($pdo, __DIR__ . '/../migrations');

$adminUser = Config::adminUser();
$adminPass = Config::adminPassword();

$userCount = (int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
if ($userCount === 0) {
    if ($adminUser === '' || $adminPass === '') {
        fwrite(STDERR, "Warning: No users exist and ADMIN_USER/ADMIN_PASSWORD are not set.\n");
    } else {
        $now = Db::nowUtc();
        $stmt = $pdo->prepare(
            'INSERT INTO users (username, password_hash, role, created_at, updated_at)
             VALUES (:u, :h, :r, :c, :m)'
        );
        $stmt->execute([
            ':u' => $adminUser,
            ':h' => password_hash($adminPass, PASSWORD_DEFAULT),
            ':r' => 'admin',
            ':c' => $now,
            ':m' => $now,
        ]);
        fwrite(STDOUT, "Bootstrapped admin user '{$adminUser}'.\n");
    }
}

fwrite(STDOUT, 'Migrations complete. Newly applied: ' . ($applied === [] ? 'none' : implode(', ', $applied)) . "\n");
