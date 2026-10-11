<?php

namespace Tests\Feature;

use App\Http\Controllers\AppleNotificationController;
use App\Models\JWTReader;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Tests\FakeAppStore;
use Tests\TestCase;

class AppleNotificationControllerTest extends TestCase
{
    private FakeAppStore $apple;

    protected function setUp(): void
    {
        parent::setUp();

        $this->apple = new FakeAppStore();

        config([
            'services.apple.bundle_id' => 'com.example.app',
            'services.apple.sandbox_forward_url' => null,
            'services.apple.root_ca_sha256' => $this->apple->rootFingerprint(),
        ]);

        Route::post('/apple/notifications', [AppleNotificationController::class, 'handle']);
        Http::fake();
    }

    public function test_it_accepts_a_notification_with_a_transaction(): void
    {
        $this->notify($this->notification('Production', ['transactionId' => '1000']))->assertOk();
        Http::assertNothingSent();
    }

    public function test_it_accepts_a_notification_without_a_transaction(): void
    {
        $this->notify($this->notification('Production'))->assertOk();
    }

    public function test_it_rejects_a_request_without_the_signed_payload(): void
    {
        $this->postJson('/apple/notifications', [])->assertStatus(422);
    }

    public function test_it_rejects_a_notification_that_apple_did_not_sign(): void
    {
        $forged = $this->apple->sign($this->notification('Production'), null, $this->apple->newKey());

        $this->postJson('/apple/notifications', ['signedPayload' => $forged])->assertStatus(422);
    }

    public function test_it_rejects_a_chain_that_is_not_made_of_certificates(): void
    {
        $header = JWTReader::base64UrlEncode(json_encode(['alg' => 'ES256', 'x5c' => ['not', 'three', 'certificates']]));
        $forged = $header . '.' . JWTReader::base64UrlEncode('{"a":1}') . '.' . JWTReader::base64UrlEncode(str_repeat('x', 64));

        $this->postJson('/apple/notifications', ['signedPayload' => $forged])->assertStatus(422);
    }

    public function test_it_rejects_a_transaction_that_apple_did_not_sign(): void
    {
        $notification = $this->notification('Production');
        $notification['data']['signedTransactionInfo'] = $this->apple->sign(['transactionId' => '1000'], null, $this->apple->newKey());

        $this->notify($notification)->assertStatus(422);
    }

    public function test_without_configuration_it_trusts_only_the_real_apple_root(): void
    {
        config(['services.apple.root_ca_sha256' => []]);

        $this->notify($this->notification('Production'))->assertStatus(422);
    }

    public function test_it_accepts_the_fingerprint_as_openssl_prints_it(): void
    {
        config(['services.apple.root_ca_sha256' => [strtoupper(implode(':', str_split($this->apple->rootFingerprint(), 2)))]]);

        $this->notify($this->notification('Production'))->assertOk();
    }

    public function test_it_rejects_a_notification_for_another_app(): void
    {
        $notification = $this->notification('Production');
        $notification['data']['bundleId'] = 'com.someone.else';

        $this->notify($notification)->assertStatus(422);
    }

    public function test_in_production_it_forwards_a_sandbox_notification(): void
    {
        $this->app->detectEnvironment(fn () => 'production');
        config(['services.apple.sandbox_forward_url' => 'https://dev.example.com/apple/notifications']);

        $signedPayload = $this->apple->sign($this->notification('Sandbox'));

        $this->postJson('/apple/notifications', ['signedPayload' => $signedPayload])->assertOk();

        Http::assertSent(fn ($request) => $request->url() === 'https://dev.example.com/apple/notifications'
            && $request['signedPayload'] === $signedPayload);
    }

    public function test_in_production_it_does_not_forward_a_production_notification(): void
    {
        $this->app->detectEnvironment(fn () => 'production');
        config(['services.apple.sandbox_forward_url' => 'https://dev.example.com/apple/notifications']);

        $this->notify($this->notification('Production'))->assertOk();

        Http::assertNothingSent();
    }

    private function notification(string $environment, ?array $transaction = null): array
    {
        $data = ['bundleId' => 'com.example.app', 'environment' => $environment];

        if ($transaction) {
            $data['signedTransactionInfo'] = $this->apple->sign($transaction);
        }

        return ['notificationType' => 'TEST', 'notificationUUID' => '6a4e2f1c', 'data' => $data];
    }

    private function notify(array $notification)
    {
        return $this->postJson('/apple/notifications', ['signedPayload' => $this->apple->sign($notification)]);
    }
}
