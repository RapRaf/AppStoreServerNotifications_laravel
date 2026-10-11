<?php

namespace App\Models;

use UnexpectedValueException;

class JWTReader
{
    public static function base64UrlDecode(string $input): string
    {
        $input = strtr($input, '-_', '+/');
        $padLength = 4 - (strlen($input) % 4);
        if ($padLength < 4) {
            $input .= str_repeat('=', $padLength);
        }

        $decoded = base64_decode($input, true);
        if ($decoded === false) {
            throw new UnexpectedValueException('Invalid base64URL encoding');
        }

        return $decoded;
    }

    public static function base64UrlEncode(string $input): string
    {
        return rtrim(strtr(base64_encode($input), '+/', '-_'), '=');
    }

    /**
     * Splits a compact JWS and decodes its three parts.
     *
     * `signingInput` is the text the signature covers: header and payload
     * exactly as they arrived, still base64url-encoded. It must not be rebuilt
     * from the decoded arrays, because encoding the same JSON again does not
     * always give back the same bytes.
     *
     * @return array{header: array, payload: array, signature: string, signingInput: string}
     */
    public static function decodeJWT(string $jwt): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new UnexpectedValueException('Invalid JWT format');
        }

        [$header, $payload, $signature] = $parts;

        $decodedHeader = json_decode(self::base64UrlDecode($header), true);
        $decodedPayload = json_decode(self::base64UrlDecode($payload), true);

        if (!is_array($decodedHeader) || !is_array($decodedPayload)) {
            throw new UnexpectedValueException('Invalid JSON in JWT');
        }

        return [
            'header' => $decodedHeader,
            'payload' => $decodedPayload,
            'signature' => self::base64UrlDecode($signature),
            'signingInput' => $header . '.' . $payload,
        ];
    }
}
