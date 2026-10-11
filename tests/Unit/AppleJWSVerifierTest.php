<?php

namespace Tests\Unit;

use App\Models\JWTReader;
use App\Services\AppleJWSVerifier;
use PHPUnit\Framework\TestCase;
use Tests\FakeAppStore;
use UnexpectedValueException;

class AppleJWSVerifierTest extends TestCase
{
    private FakeAppStore $apple;
    private AppleJWSVerifier $verifier;

    protected function setUp(): void
    {
        $this->apple = new FakeAppStore();
        $this->verifier = new AppleJWSVerifier([$this->apple->rootFingerprint()]);
    }

    public function test_it_returns_the_payload_of_a_valid_jws(): void
    {
        $payload = ['notificationType' => 'TEST', 'data' => ['bundleId' => 'com.example.app']];

        $this->assertSame($payload, $this->verifier->verify($this->apple->sign($payload)));
    }

    public function test_it_verifies_the_bytes_that_were_signed_not_a_new_encoding_of_them(): void
    {
        // Encoding this JSON again would change it: spaces, an empty object,
        // an escaped slash, an escaped accent and a float all come out different.
        $json = '{ "url": "https:\/\/example.com", "empty": {}, "name": "caffè", "price": 1.0 }';

        $this->assertSame('https://example.com', $this->verifier->verify($this->apple->sign($json))['url']);
    }

    public function test_it_rejects_a_payload_changed_after_signing(): void
    {
        [$header, , $signature] = explode('.', $this->apple->sign(['price' => 10]));
        $forged = $header . '.' . JWTReader::base64UrlEncode('{"price":0}') . '.' . $signature;

        $this->expectRejection('Signature verification failed', $forged);
    }

    public function test_it_rejects_a_signature_made_with_another_key(): void
    {
        $this->expectRejection('Signature verification failed', $this->apple->sign(['a' => 1], null, $this->apple->newKey()));
    }

    public function test_it_rejects_a_chain_that_does_not_end_with_a_trusted_root(): void
    {
        // The default trusted root is the real Apple one, not the fake.
        $this->expectRejection('Root certificate is not the Apple Root CA', $this->apple->sign(['a' => 1]), new AppleJWSVerifier());
    }

    public function test_it_rejects_a_leaf_signed_by_another_intermediate(): void
    {
        $otherKey = $this->apple->newKey();
        $other = $this->apple->newCertificate('Other Intermediate CA', 'intermediate', $otherKey, $this->apple->root, $this->apple->rootKey);

        $jws = $this->apple->sign(['a' => 1], [$this->apple->leaf, $other, $this->apple->root]);

        $this->expectRejection('Leaf certificate is not signed by the intermediate certificate', $jws);
    }

    public function test_it_rejects_a_leaf_that_was_not_issued_for_the_app_store(): void
    {
        // What a certificate issued to a developer under the same root looks like.
        $key = $this->apple->newKey();
        $leaf = $this->apple->newCertificate('Developer', 'leaf_unmarked', $key, $this->apple->intermediate, $this->apple->intermediateKey);

        $jws = $this->apple->sign(['a' => 1], [$leaf, $this->apple->intermediate, $this->apple->root], $key);

        $this->expectRejection('Leaf certificate was not issued for the App Store', $jws);
    }

    public function test_it_rejects_an_intermediate_without_the_apple_marker(): void
    {
        $intermediateKey = $this->apple->newKey();
        $intermediate = $this->apple->newCertificate('Other CA', 'intermediate_unmarked', $intermediateKey, $this->apple->root, $this->apple->rootKey);
        $key = $this->apple->newKey();
        $leaf = $this->apple->newCertificate('Leaf', 'leaf', $key, $intermediate, $intermediateKey);

        $jws = $this->apple->sign(['a' => 1], [$leaf, $intermediate, $this->apple->root], $key);

        $this->expectRejection('Intermediate certificate is not an Apple certificate authority', $jws);
    }

    public function test_it_rejects_an_expired_certificate(): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('A certificate of the chain is expired or not yet valid');

        $this->verifier->verify($this->apple->sign(['a' => 1]), time() + 365 * 24 * 60 * 60);
    }

    public function test_it_rejects_an_algorithm_other_than_es256(): void
    {
        $this->expectRejection('Algorithm is not ES256', $this->apple->sign(['a' => 1], null, null, 'HS256'));
    }

    public function test_it_rejects_a_chain_of_the_wrong_length(): void
    {
        $jws = $this->apple->sign(['a' => 1], [$this->apple->leaf, $this->apple->intermediate]);

        $this->expectRejection('x5c must contain three certificates', $jws);
    }

    public function test_it_rejects_what_is_not_a_jws(): void
    {
        $this->expectRejection('Invalid JWT format', 'not.a-jws');
    }

    private function expectRejection(string $message, string $jws, ?AppleJWSVerifier $verifier = null): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage($message);

        ($verifier ?? $this->verifier)->verify($jws);
    }
}
