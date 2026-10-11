<?php

namespace App\Services;

use App\Models\JWTReader;
use OpenSSLCertificate;
use UnexpectedValueException;

/**
 * Verifies the JWS that Apple signs for the App Store: server notifications,
 * transactions and renewal information.
 *
 * It has no dependency on Laravel, so it can be used and tested on its own.
 */
class AppleJWSVerifier
{
    /**
     * SHA-256 fingerprint of "Apple Root CA - G3", the certificate every
     * App Store chain must end with. To check it yourself:
     *
     *   curl -s https://www.apple.com/certificateauthority/AppleRootCA-G3.cer \
     *     | openssl x509 -inform DER -noout -fingerprint -sha256
     */
    public const APPLE_ROOT_CA_G3_SHA256 = '63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179';

    /**
     * Extensions that mark the two certificates Apple uses for the App Store.
     * Without these checks any certificate issued under the same root would
     * be accepted, including the ones Apple issues to developers.
     */
    private const LEAF_OID = '1.2.840.113635.100.6.11.1';
    private const INTERMEDIATE_OID = '1.2.840.113635.100.6.2.1';

    /** @var string[] */
    private array $trustedRootFingerprints;

    /**
     * @param string[] $trustedRootFingerprints SHA-256 fingerprints, in hex
     */
    public function __construct(array $trustedRootFingerprints = [self::APPLE_ROOT_CA_G3_SHA256])
    {
        $this->trustedRootFingerprints = array_map(
            fn (string $fingerprint) => strtolower(str_replace(':', '', $fingerprint)),
            $trustedRootFingerprints
        );
    }

    /**
     * Returns the payload of the JWS once the certificate chain and the
     * signature have been verified.
     *
     * @param int|null $at Unix time the certificates must be valid at. The
     *                     default is now, which is right for a notification
     *                     that has just arrived.
     *
     * @throws UnexpectedValueException if the JWS cannot be trusted
     */
    public function verify(string $jws, ?int $at = null): array
    {
        $jwt = JWTReader::decodeJWT($jws);

        if (($jwt['header']['alg'] ?? null) !== 'ES256') {
            throw new UnexpectedValueException('Algorithm is not ES256');
        }

        $leafCert = $this->verifyCertificateChain($jwt['header']['x5c'] ?? null, $at ?? time());

        $this->verifySignature($jwt['signingInput'], $jwt['signature'], $leafCert);

        return $jwt['payload'];
    }

    /**
     * Checks the `x5c` chain (leaf, intermediate, root) and returns the leaf
     * certificate, whose public key signed the JWS.
     */
    private function verifyCertificateChain(mixed $x5c, int $at): OpenSSLCertificate
    {
        if (!is_array($x5c) || count($x5c) !== 3) {
            throw new UnexpectedValueException('x5c must contain three certificates');
        }

        [$leafCert, $intermediateCert, $rootCert] = array_map(function ($certificate) {
            // @: on text that is not a certificate PHP also raises a warning,
            // which Laravel would turn into a server error.
            $cert = is_string($certificate) ? @openssl_x509_read($this->getPEMFromX5C($certificate)) : false;
            if (!$cert) {
                throw new UnexpectedValueException('Failed to load a certificate of the chain');
            }

            return $cert;
        }, array_values($x5c));

        if (!in_array(openssl_x509_fingerprint($rootCert, 'sha256'), $this->trustedRootFingerprints, true)) {
            throw new UnexpectedValueException('Root certificate is not the Apple Root CA');
        }

        // openssl_x509_verify returns 1, 0 or -1 (on error): only 1 is a pass.
        if (openssl_x509_verify($leafCert, $intermediateCert) !== 1) {
            throw new UnexpectedValueException('Leaf certificate is not signed by the intermediate certificate');
        }

        if (openssl_x509_verify($intermediateCert, $rootCert) !== 1) {
            throw new UnexpectedValueException('Intermediate certificate is not signed by the root certificate');
        }

        $leaf = openssl_x509_parse($leafCert);
        $intermediate = openssl_x509_parse($intermediateCert);
        $root = openssl_x509_parse($rootCert);

        foreach ([$leaf, $intermediate, $root] as $certificate) {
            if (!$certificate || $at < $certificate['validFrom_time_t'] || $at > $certificate['validTo_time_t']) {
                throw new UnexpectedValueException('A certificate of the chain is expired or not yet valid');
            }
        }

        if (!isset($leaf['extensions'][self::LEAF_OID])) {
            throw new UnexpectedValueException('Leaf certificate was not issued for the App Store');
        }

        if (
            !isset($intermediate['extensions'][self::INTERMEDIATE_OID])
            || !str_contains($intermediate['extensions']['basicConstraints'] ?? '', 'CA:TRUE')
        ) {
            throw new UnexpectedValueException('Intermediate certificate is not an Apple certificate authority');
        }

        return $leafCert;
    }

    private function getPEMFromX5C(string $x5c): string
    {
        return "-----BEGIN CERTIFICATE-----\n" . chunk_split($x5c, 64, "\n") . "-----END CERTIFICATE-----\n";
    }

    private function verifySignature(string $signingInput, string $signature, OpenSSLCertificate $leafCert): void
    {
        $publicKey = openssl_pkey_get_public($leafCert);
        $keyDetails = $publicKey ? openssl_pkey_get_details($publicKey) : false;

        if (
            !$keyDetails
            || $keyDetails['type'] !== OPENSSL_KEYTYPE_EC
            || ($keyDetails['ec']['curve_name'] ?? null) !== 'prime256v1'
        ) {
            throw new UnexpectedValueException('Leaf certificate does not hold a P-256 public key');
        }

        $verificationResult = openssl_verify(
            $signingInput,
            $this->convertSignatureToDER($signature),
            $publicKey,
            OPENSSL_ALGO_SHA256
        );

        if ($verificationResult !== 1) {
            throw new UnexpectedValueException('Signature verification failed');
        }
    }

    /**
     * A JWS carries the ES256 signature as the two 32-byte integers r and s,
     * one after the other. OpenSSL wants them as an ASN.1 DER sequence.
     */
    private function convertSignatureToDER(string $signature): string
    {
        if (strlen($signature) !== 64) {
            throw new UnexpectedValueException('Invalid signature length: ' . strlen($signature));
        }

        $integers = '';
        foreach (str_split($signature, 32) as $integer) {
            $integer = ltrim($integer, "\x00");

            // A DER integer is signed: a leading zero keeps it positive.
            if ($integer === '' || ord($integer[0]) > 0x7f) {
                $integer = "\x00" . $integer;
            }

            $integers .= "\x02" . chr(strlen($integer)) . $integer;
        }

        return "\x30" . chr(strlen($integers)) . $integers;
    }
}
