<?php

declare(strict_types=1);

require_once __DIR__ . '/Config.php';
require_once __DIR__ . '/Db.php';

final class Quota
{
    public static function today(): string
    {
        return gmdate('Y-m-d');
    }

    public static function limitForUser(PDO $pdo, int $userId): int
    {
        $stmt = $pdo->prepare('SELECT daily_limit FROM users WHERE id = :id');
        $stmt->execute([':id' => $userId]);
        $row = $stmt->fetch();
        if ($row && $row['daily_limit'] !== null) {
            return max(1, (int) $row['daily_limit']);
        }
        return Config::dailyLimit();
    }

    /**
     * @return array{used: int, limit: int, remaining: int, day: string}
     */
    public static function status(PDO $pdo, int $userId, ?string $day = null): array
    {
        $day ??= self::today();
        $limit = self::limitForUser($pdo, $userId);

        $stmt = $pdo->prepare('SELECT used FROM quota WHERE user_id = :uid AND day = :day');
        $stmt->execute([':uid' => $userId, ':day' => $day]);
        $used = (int) ($stmt->fetchColumn() ?: 0);

        return [
            'used' => $used,
            'limit' => $limit,
            'remaining' => max(0, $limit - $used),
            'day' => $day,
        ];
    }

    /**
     * Atomically reserve $count checks for today. Returns false if over daily limit.
     * Note: safe to call either standalone or inside an existing write transaction.
     */
    public static function reserve(PDO $pdo, int $userId, int $count, ?string $day = null): bool
    {
        if ($count <= 0) {
            return true;
        }

        $day ??= self::today();
        $limit = self::limitForUser($pdo, $userId);

        $run = static function (PDO $conn) use ($userId, $count, $day, $limit): bool {
            $ins = $conn->prepare('INSERT OR IGNORE INTO quota (user_id, day, used) VALUES (:uid, :day, 0)');
            $ins->execute([':uid' => $userId, ':day' => $day]);

            $upd = $conn->prepare(
                'UPDATE quota SET used = used + :n WHERE user_id = :uid AND day = :day AND used + :n2 <= :lim'
            );
            $upd->execute([
                ':n' => $count,
                ':uid' => $userId,
                ':day' => $day,
                ':n2' => $count,
                ':lim' => $limit,
            ]);

            return $upd->rowCount() === 1;
        };

        if ($pdo->inTransaction()) {
            return $run($pdo);
        }

        return Db::writeTransaction($pdo, $run);
    }

    public static function refund(PDO $pdo, int $userId, int $count, ?string $day = null): void
    {
        if ($count <= 0) {
            return;
        }
        $day ??= self::today();

        $run = static function (PDO $conn) use ($userId, $count, $day): void {
            $upd = $conn->prepare(
                'UPDATE quota SET used = MAX(0, used - :n) WHERE user_id = :uid AND day = :day'
            );
            $upd->execute([
                ':n' => $count,
                ':uid' => $userId,
                ':day' => $day,
            ]);
        };

        if ($pdo->inTransaction()) {
            $run($pdo);
            return;
        }

        Db::writeTransaction($pdo, $run);
    }
}
