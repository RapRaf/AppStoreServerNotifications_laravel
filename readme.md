## App Store Server Notifications

Validation of [App Store Server Notifications V2](https://developer.apple.com/documentation/appstoreservernotifications) in a Laravel application: the certificate chain and the signature of every JWS are verified before its content is used.

The code is explained step by step in [this article](https://raffaelebertani.com/en/articles/apple-signature-tutorial) ([Italian version](https://raffaelebertani.com/articoli/apple-signature-tutorial)).

### Files

| File | Copy to | What it does |
| --- | --- | --- |
| `AppleNotificationController.php` | `app/Http/Controllers` | Receives the notification and decides what to do with it |
| `AppleJWSVerifier.php` | `app/Services` | Verifies a JWS signed by Apple and returns its payload. It does not depend on Laravel |
| `JWTReader.php` | `app/Models` | Decodes a compact JWS. Any JWT library can take its place |
| `tests/` | `tests` | Tests for the verifier and the controller, with a fake Apple certificate chain |

### What is verified

For the notification, and for the transaction and renewal information inside it:

- the algorithm is ES256;
- `x5c` holds three certificates, each signed by the next one;
- the root is Apple Root CA - G3, recognized by its SHA-256 fingerprint;
- no certificate is expired;
- leaf and intermediate carry the extensions Apple uses for the App Store (OID `1.2.840.113635.100.6.11.1` and `1.2.840.113635.100.6.2.1`);
- the signature matches the header and payload exactly as they were received.

Then the controller checks that the notification is about your app (`bundleId`).

Certificate revocation (OCSP) is not checked.

### Setup

Requires PHP 8.0 or later with the `openssl` extension.

Add the route to `routes/api.php`, so that it is not behind CSRF protection:

```php
Route::post('/route/path', [AppleNotificationController::class, 'handle']);
```

Add your app to `config/services.php`:

```php
'apple' => [
    // Notifications for any other bundle id are rejected.
    'bundle_id' => env('APPLE_BUNDLE_ID'),
    // Optional: where the production server sends the sandbox notifications it receives.
    'sandbox_forward_url' => env('APPLE_SANDBOX_FORWARD_URL'),
    // Optional, see "When Apple changes its certificates".
    'root_ca_sha256' => array_filter(explode(',', (string) env('APPLE_ROOT_CA_SHA256'))),
],
```

Then write your own logic where `handle` says `YOUR CODE HERE`.

### When Apple changes its certificates

Nothing to do for the certificates Apple renews from time to time: the leaf and the intermediate travel inside every notification and are never stored here. They are recognized by who signed them and by their two extensions, which say what a certificate is for and stay the same when it is renewed.

The only fixed value is the fingerprint of the root, Apple Root CA - G3, valid until 2039. Every verification needs one trusted starting point and this is it: a root that could change by itself would not prove anything. If Apple moves the App Store to a new root, add its fingerprint to `.env` without touching the code, next to the old one while both are in use:

```bash
APPLE_ROOT_CA_SHA256=<old fingerprint>,<new fingerprint>
```

The fingerprint is what this command prints after `Fingerprint=`, with or without the colons:

```bash
openssl x509 -inform DER -in AppleRootCA-G3.cer -noout -fingerprint -sha256
```

### Tests

```bash
php artisan test --filter Apple
```

To try the endpoint with a real notification, ask Apple for a test one with [Request a Test Notification](https://developer.apple.com/documentation/appstoreserverapi/request-a-test-notification).
