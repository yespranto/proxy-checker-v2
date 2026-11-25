<?php

declare(strict_types=1);

require_once __DIR__ . '/Config.php';

final class Crypto
{
    private static function deriveKey(string $context): string
    {
        $secret = Config::secretKey();
        return sodium_crypto_generichash(
            $secret,
            $context,
            SODIUM_CRYPTO_SECRETBOX_KEYBYTES
        );
    }

    public static function encrypt(?string $plaintext): ?string
    {
        if ($plaintext === null || $plaintext === '') {
            return null;
        }

        $key = self::deriveKey('proxy-password-box-v1');
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $cipher = sodium_crypto_secretbox($plaintext, $nonce, $key);
        sodium_memzero($key);

        return $nonce . $cipher;
    }

    public static function decrypt(?string $blob): ?string
    {
        if ($blob === null || $blob === '') {
            return null;
        }

        $minLen = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES;
        if (strlen($blob) < $minLen) {
            return null;
        }

        $nonce = substr($blob, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $cipher = substr($blob, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $key = self::deriveKey('proxy-password-box-v1');

        $plain = sodium_crypto_secretbox_open($cipher, $nonce, $key);
        sodium_memzero($key);

        return $plain === false ? null : $plain;
    }

    public static function signingKey(): string
    {
        return self::deriveKey('session-and-hmac-key-v1');
    }
}
