<?php

namespace Tests;

use App\Models\JWTReader;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;

/**
 * A stand-in for Apple in the tests: a root, an intermediate and a leaf
 * certificate shaped like the real ones, and a way to sign a JWS with them.
 */
class FakeAppStore
{
    public OpenSSLAsymmetricKey $rootKey;
    public OpenSSLCertificate $root;
    public OpenSSLAsymmetricKey $intermediateKey;
    public OpenSSLCertificate $intermediate;
    public OpenSSLAsymmetricKey $leafKey;
    public OpenSSLCertificate $leaf;

    private string $config;
    private int $serial = 1;

    public function __construct()
    {
        $this->config = tempnam(sys_get_temp_dir(), 'openssl');
        file_put_contents($this->config, <<<'CNF'
            [req]
            distinguished_name = dn
            default_bits = 2048
            [dn]
            [root]
            basicConstraints = critical, CA:TRUE
            keyUsage = critical, keyCertSign, cRLSign
            [intermediate]
            basicConstraints = critical, CA:TRUE, pathlen:0
            keyUsage = critical, keyCertSign, cRLSign
            1.2.840.113635.100.6.2.1 = DER:0500
            [intermediate_unmarked]
            basicConstraints = critical, CA:TRUE, pathlen:0
            keyUsage = critical, keyCertSign, cRLSign
            [leaf]
            basicConstraints = critical, CA:FALSE
            keyUsage = critical, digitalSignature
            1.2.840.113635.100.6.11.1 = DER:0500
            [leaf_unmarked]
            basicConstraints = critical, CA:FALSE
            keyUsage = critical, digitalSignature
            CNF);

        $this->rootKey = $this->newKey();
        $this->root = $this->newCertificate('Fake Root CA', 'root', $this->rootKey);

        $this->intermediateKey = $this->newKey();
        $this->intermediate = $this->newCertificate('Fake Intermediate CA', 'intermediate', $this->intermediateKey, $this->root, $this->rootKey);

        $this->leafKey = $this->newKey();
        $this->leaf = $this->newCertificate('Fake Leaf', 'leaf', $this->leafKey, $this->intermediate, $this->intermediateKey);
    }

    public function __destruct()
    {
        @unlink($this->config);
    }

    public function newKey(): OpenSSLAsymmetricKey
    {
        return openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
            'config' => $this->config,
        ]);
    }

    /**
     * @param string $extensions Section of the OpenSSL config above
     * @param OpenSSLCertificate|null $issuer null for a self-signed certificate
     */
    public function newCertificate(
        string $name,
        string $extensions,
        OpenSSLAsymmetricKey $key,
        ?OpenSSLCertificate $issuer = null,
        ?OpenSSLAsymmetricKey $issuerKey = null,
        int $days = 30
    ): OpenSSLCertificate {
        $options = ['config' => $this->config, 'digest_alg' => 'sha256', 'x509_extensions' => $extensions];
        $request = openssl_csr_new(['commonName' => $name], $key, $options);

        return openssl_csr_sign($request, $issuer, $issuerKey ?? $key, $days, $options, $this->serial++);
    }

    public function rootFingerprint(): string
    {
        return openssl_x509_fingerprint($this->root, 'sha256');
    }

    /**
     * A compact JWS signed like Apple does: ES256, certificates in `x5c`.
     *
     * @param array|string $payload An array, or the JSON text to sign as it is
     * @param OpenSSLCertificate[]|null $chain Leaf, intermediate, root
     */
    public function sign(
        array|string $payload,
        ?array $chain = null,
        ?OpenSSLAsymmetricKey $key = null,
        string $alg = 'ES256'
    ): string {
        $chain ??= [$this->leaf, $this->intermediate, $this->root];

        $header = json_encode(['alg' => $alg, 'x5c' => array_map([$this, 'x5c'], $chain)]);
        $payload = is_string($payload) ? $payload : json_encode($payload);

        $signingInput = JWTReader::base64UrlEncode($header) . '.' . JWTReader::base64UrlEncode($payload);

        openssl_sign($signingInput, $signature, $key ?? $this->leafKey, OPENSSL_ALGO_SHA256);

        return $signingInput . '.' . JWTReader::base64UrlEncode($this->derToRaw($signature));
    }

    /** A certificate the way `x5c` carries it: base64 of the DER encoding. */
    private function x5c(OpenSSLCertificate $certificate): string
    {
        openssl_x509_export($certificate, $pem);

        return preg_replace('/-----[A-Z ]+-----|\s/', '', $pem);
    }

    /** OpenSSL signs in ASN.1 DER, a JWS wants r and s as 32 bytes each. */
    private function derToRaw(string $der): string
    {
        $offset = 2;
        $raw = '';
        foreach ([0, 1] as $ignored) {
            $length = ord($der[$offset + 1]);
            $integer = ltrim(substr($der, $offset + 2, $length), "\x00");
            $raw .= str_pad($integer, 32, "\x00", STR_PAD_LEFT);
            $offset += 2 + $length;
        }

        return $raw;
    }
}
