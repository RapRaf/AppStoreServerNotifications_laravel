<?php

namespace App\Http\Controllers;

use App\Services\AppleJWSVerifier;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;
use UnexpectedValueException;

class AppleNotificationController extends Controller
{
    public function handle(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'signedPayload' => 'required|string',
        ]);

        if ($validator->fails()) {
            Log::error('Validation failed', ['errors' => $validator->errors()]);
            return response()->json(['message' => 'Malformed request'], 422);
        }

        $signedPayload = $validator->validated()['signedPayload'];

        // Trusts Apple Root CA - G3. Should Apple ever move the App Store to
        // another root, set its fingerprint in services.apple.root_ca_sha256
        // instead of changing the code.
        $verifier = new AppleJWSVerifier(
            (array) (config('services.apple.root_ca_sha256') ?: AppleJWSVerifier::APPLE_ROOT_CA_G3_SHA256)
        );

        try {
            $notifyData = $verifier->verify($signedPayload);

            // What the notification is about. Which of these is present
            // depends on the notification type.
            $details = $notifyData['data']
                ?? $notifyData['summary']
                ?? $notifyData['externalPurchaseToken']
                ?? $notifyData['appData']
                ?? [];

            // Not every notification carries a transaction: a TEST one has none.
            $purchaseData = isset($details['signedTransactionInfo'])
                ? $verifier->verify($details['signedTransactionInfo'])
                : null;

            // Only for auto-renewable subscriptions.
            $renewalData = isset($details['signedRenewalInfo'])
                ? $verifier->verify($details['signedRenewalInfo'])
                : null;
        } catch (UnexpectedValueException $e) {
            Log::error('Apple notification rejected: ' . $e->getMessage());
            return response()->json(['message' => 'Invalid signed payload'], 422);
        }

        // The signature only proves that Apple wrote the notification, not
        // that it is about this app: Apple signs the notifications of every
        // app with the same certificates.
        if (($details['bundleId'] ?? null) !== config('services.apple.bundle_id')) {
            Log::error('Apple notification rejected: it is for another app', ['bundleId' => $details['bundleId'] ?? null]);
            return response()->json(['message' => 'Invalid signed payload'], 422);
        }

        if ($this->isSandbox($details) && app()->environment('production')) {
            return $this->forwardToDevServer($signedPayload);
        }

        /**
         * YOUR CODE HERE
         *
         * READ AND HANDLE PURCHASE
         *
         * Apple sends the same notification again when it gets no answer:
         * $notifyData['notificationUUID'] tells you if you already handled it.
         */

        return response()->json(['message' => 'Notification processed successfully'], 200);
    }

    private function isSandbox(array $details): bool
    {
        // An external purchase token has no environment field: in the sandbox
        // its id starts with "SANDBOX".
        return ($details['environment'] ?? null) === 'Sandbox'
            || str_starts_with($details['externalPurchaseId'] ?? '', 'SANDBOX');
    }

    /**
     * Sandbox notifications that reach the production server are passed on,
     * as they are, to the server set in services.apple.sandbox_forward_url.
     * Without one they are acknowledged and dropped.
     */
    private function forwardToDevServer(string $signedPayload)
    {
        $url = config('services.apple.sandbox_forward_url');

        if (!$url) {
            return response()->json(['message' => 'Sandbox notification ignored'], 200);
        }

        try {
            $response = Http::timeout(10)->post($url, ['signedPayload' => $signedPayload]);

            if ($response->successful()) {
                Log::info('Forwarded Apple notification to DEV server', [
                    'response' => $response->json()
                ]);
                return response()->json(['message' => 'Notification forwarded successfully'], 200);
            } else {
                Log::error('Failed to forward Apple notification', [
                    'error' => $response->body(),
                    'status' => $response->status()
                ]);
                return response()->json(['message' => 'Failed to forward request'], 502);
            }
        } catch (Exception $e) {
            Log::error('Failed to forward Apple notification', ['error' => $e->getMessage()]);
            return response()->json(['message' => 'Failed to forward request'], 502);
        }
    }
}
