<?php

declare(strict_types=1);

require_once __DIR__ . '/Config.php';

final class Db
{
    private static ?PDO $instance = null;

    public static function pdo(): PDO
    {
        if (self::$instance !== null) {
            return self::$instance;
        }

        $path = Config::dbPath();
        $dir = dirname($path);
        if (!is_dir($dir) && !@mkdir($dir, 0770, true) && !is_dir($dir)) {
            throw new RuntimeException('Unable to create database directory: ' . $dir);
        }

        $pdo = new PDO('sqlite:' . $path, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);

        $pdo->exec('PRAGMA journal_mode=WAL;');
        $pdo->exec('PRAGMA busy_timeout=5000;');
        $pdo->exec('PRAGMA foreign_keys=ON;');
        $pdo->exec('PRAGMA synchronous=NORMAL;');

        self::$instance = $pdo;
        return $pdo;
    }

    /**
     * Execute a callback inside an IMMEDIATE SQLite transaction to avoid lock upgrade deadlocks.
     *
     * @template T
     * @param callable(PDO): T $fn
     * @return T
     */
    public static function writeTransaction(PDO $pdo, callable $fn): mixed
    {
        $pdo->exec('BEGIN IMMEDIATE');
        try {
            $result = $fn($pdo);
            $pdo->exec('COMMIT');
            return $result;
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->exec('ROLLBACK');
            } else {
                try {
                    $pdo->exec('ROLLBACK');
                } catch (Throwable) {
                    // Already rolled back
                }
            }
            throw $e;
        }
    }

    /**
     * Apply pending NNN_*.sql migration files in order.
     *
     * @return list<int> Applied version numbers
     */
    public static function migrate(PDO $pdo, string $migrationsDir): array
    {
        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)'
        );

        $appliedRows = $pdo->query('SELECT version FROM schema_migrations')->fetchAll(PDO::FETCH_COLUMN);
        $applied = array_flip(array_map('intval', $appliedRows));

        $files = glob(rtrim($migrationsDir, '/\\') . '/*.sql') ?: [];
        sort($files, SORT_STRING);

        $newlyApplied = [];
        foreach ($files as $file) {
            $base = basename($file);
            if (!preg_match('/^(\d+)_/', $base, $m)) {
                continue;
            }
            $version = (int) $m[1];
            if (isset($applied[$version])) {
                continue;
            }

            $sql = file_get_contents($file);
            if ($sql === false) {
                throw new RuntimeException('Failed to read migration: ' . $base);
            }

            self::writeTransaction($pdo, static function (PDO $conn) use ($sql, $version): void {
                $conn->exec($sql);
                $stmt = $conn->prepare('INSERT INTO schema_migrations (version, applied_at) VALUES (:v, :at)');
                $stmt->execute([
                    ':v' => $version,
                    ':at' => gmdate('Y-m-d\TH:i:s\Z'),
                ]);
            });

            $newlyApplied[] = $version;
        }

        return $newlyApplied;
    }

    public static function nowUtc(): string
    {
        return gmdate('Y-m-d\TH:i:s\Z');
    }
}
