<?php

namespace App\Models;

use Exception;

class JWTReader
{
    public static function base64UrlDecode($input)
    {
        $input = strtr($input, '-_', '+/');
        $padLength = 4 - (strlen($input) % 4);
        if ($padLength < 4) {
            $input .= str_repeat('=', $padLength);
        }

        $decoded = base64_decode($input, true);
        if ($decoded === false) {
            throw new Exception('Invalid base64URL encoding');
        }

        return $decoded;
    }

    public static function decodeJWT($jwt)
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new Exception('Invalid JWT format');
        }

        [$header, $payload, $signature] = $parts;

        $decodedHeader = json_decode(self::base64UrlDecode($header), true);
        $decodedPayload = json_decode(self::base64UrlDecode($payload), true);

        if (!$decodedHeader || !$decodedPayload) {
            throw new Exception('Invalid JSON in JWT');
        }

        return [
            'header' => $decodedHeader,
            'payload' => $decodedPayload,
            'signature' => $signature
        ];
    }
}
