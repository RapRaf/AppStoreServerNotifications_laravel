<?php

namespace App\Http\Controllers;

use App\Models\JWTReader;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Facades\Validator;

class AppleNotificationController extends Controller
{
    public $certFilePath = '/tmp/root_certificate.der';
    public $pemFilePath = '/tmp/root_certificate.pem';

    public function handle(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'signedPayload' => 'required|string',
        ]);

        if ($validator->fails()) {
            Log::error('Validation failed', ['errors' => $validator->errors()]);
            return response()->json(['message' => 'Malformed request'], 422);
        }

        $validated = $validator->validated();

        try {
            $decodedNotifyJWS = JWTReader::decodeJWT($validated['signedPayload']);
        } catch (Exception $e) {
            Log::error('Notify JWS Decoding Failed: ' . $e->getMessage());
            return response()->json(['message' => 'Invalid JWT'], 422);
        }

        if (!isset($decodedNotifyJWS['header']) || !isset($decodedNotifyJWS['payload']) || !isset($decodedNotifyJWS['signature'])) {
            Log::error('Notify JWS not invalid');
            return response()->json(['message' => 'Invalid JWT'], 422);
        }

        try {
            $decodedPurchaseJWS = JWTReader::decodeJWT($decodedNotifyJWS['payload']['data']['signedTransactionInfo']);
        } catch (Exception $e) {
            Log::error('Purchase JWS Decoding Failed: ' . $e->getMessage());
            return response()->json(['message' => 'Invalid JWT'], 422);
        }

        if (!isset($decodedPurchaseJWS['header']) || !isset($decodedPurchaseJWS['payload']) || !isset($decodedPurchaseJWS['signature'])) {
            Log::error('Purchase JWS not invalid');
            return response()->json(['message' => 'Invalid JWT'], 422);
        }

        switch ($this->validatedSignedJWS($decodedNotifyJWS)) {
            case 1:
                Log::error('Notify Certificate chain verification failed');
                break;
            case 2:
                Log::error('Notify Signature verification failed');
                break;
            default:
                break;
        }

        switch ($this->validatedSignedJWS($decodedPurchaseJWS)) {
            case 1:
                Log::error('Purchase Certificate chain verification failed');
                break;
            case 2:
                Log::error('Purchase Signature verification failed');
                break;
            default:
                break;
        }

        $notifyData = $decodedNotifyJWS['payload'];

        $purchaseData = $decodedPurchaseJWS['payload'];

        /**
         * YOUR CODE HERE
         * 
         * READ AND HANDLE PURCHASE
         */
    }

    private function validatedSignedJWS($decodedPayload)
    {
        $leafCertPEM = $this->verifyCertificateChain($decodedPayload);

        if ($leafCertPEM == null) return 1;

        if (!$this->verifyAppleSignature($decodedPayload, $leafCertPEM)) return 2;

        return 0;
    }

    private function fetchAppleRootCertificate()
    {
        $certUrl = 'https://www.apple.com/certificateauthority/AppleRootCA-G3.cer';

        $ch = curl_init($certUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        $certData = curl_exec($ch);
        curl_close($ch);

        if ($certData === false) {
            throw new Exception('Failed to download Apple root certificate.');
        }

        file_put_contents($this->certFilePath, $certData);

        exec("openssl x509 -inform DER -in $this->certFilePath -out $this->pemFilePath", $output, $returnVar);

        if ($returnVar !== 0) {
            throw new Exception('Failed to convert DER to PEM format.');
        }

        $certificatePEM = $this->getRootCertificateFromStorage();

        /** REMOVING CERTIFICATES FROM DISK */
        unlink($this->certFilePath);
        unlink($this->pemFilePath); /// COMMENT IF YOU ARE NOT CACHING SOMEWHERE ELSE
        /** */

        /**
         * HERE I AM CACHING IN REDIS WITH EXPIRATION IN 7 DAYS
         */
        Redis::set('apple_root_certificate', $certificatePEM);
        Redis::expire('apple_root_certificate', 7 * 24 * 60 * 60);

        return $certificatePEM;
    }

    private function getCachedAppleRootCertificate()
    {
        return Redis::get('apple_root_certificate') ??  $this->fetchAppleRootCertificate();

        /** 
         * IF YOU ARE NOT CACHING IN MEMORY
         */
        // return $this->getRootCertificateFromStorage() ??  $this->fetchAppleRootCertificate();
    }

    private function getRootCertificateFromStorage()
    {
        $tempPEM = file_get_contents($this->pemFilePath);
        if (!$tempPEM) {
            return null;
        }

        $certResource = openssl_x509_read($tempPEM);
        if (!$certResource) {
            return null;
        }

        return openssl_x509_export($certResource, $certificatePEM) ? $certificatePEM : null;
    }

    private function getPEMFromX5C($x5c)
    {
        return "-----BEGIN CERTIFICATE-----\n" . chunk_split($x5c, 64, "\n") . "-----END CERTIFICATE-----\n";
    }

    private function verifyCertificateChain($decodedPayload)
    {
        $appleRootCertPEM = $this->getCachedAppleRootCertificate();

        $leafCertPEM = $this->getPEMFromX5C($decodedPayload['header']['x5c'][0]);
        $intermediateCertPEM = $this->getPEMFromX5C($decodedPayload['header']['x5c'][1]);
        $rootCertPEM = $this->getPEMFromX5C($decodedPayload['header']['x5c'][2]);


        if (trim($rootCertPEM) !== trim($appleRootCertPEM)) {
            Log::error('Root certificate does not match Apple Root CA, cleaning cache and downloading fresh root cert');
            Redis::del('apple_root_certificate');

            /** UNCOMMENT IF NOT USING REDIS */
            // unlink($this->pemFilePath); 

            $appleRootCertPEM = $this->getCachedAppleRootCertificate();
            if (trim($rootCertPEM) !== trim($appleRootCertPEM)) {
                Log::error('Root certificate does not match Apple Root CA');
                return null;
            }
        }

        $leafCert = openssl_x509_read($leafCertPEM);
        $intermediateCert = openssl_x509_read($intermediateCertPEM);
        $rootCert = openssl_x509_read($rootCertPEM);

        if (!$leafCert || !$intermediateCert || !$rootCert) {
            Log::error('Failed to load certificates');
            return null;
        }

        if (!openssl_x509_verify($leafCert, $intermediateCert)) {
            Log::error('Leaf certificate is not signed by Intermediate certificate');
            return null;
        }

        if (!openssl_x509_verify($intermediateCert, $rootCert)) {
            Log::error('Intermediate certificate is not signed by Root certificate');
            return null;
        }

        return $leafCert;
    }

    private function extractCertificatePublicKey($leafCertPEM)
    {
        $cert = openssl_x509_read($leafCertPEM);
        if (!$cert) {
            Log::error('Invalid leaf certificate, unable to read.');
            return false;
        }

        $publicKeyResource = openssl_pkey_get_public($cert);
        if (!$publicKeyResource) {
            Log::error('Failed to extract public key from leaf certificate');
            return false;
        }

        $keyDetails = openssl_pkey_get_details($publicKeyResource);
        if (!$keyDetails || !isset($keyDetails['key'])) {
            Log::error('Failed to retrieve public key details');
            return false;
        }
        return $keyDetails['key'];
    }


    private function verifyAppleSignature($decodedPayload, $leafCertPEM)
    {
        $publicKey = $this->extractCertificatePublicKey($leafCertPEM);

        if (!$publicKey) {
            Log::error('Failed to extract public key from leaf certificate.');
            return false;
        }

        $decodedSignature = JWTReader::base64UrlDecode($decodedPayload['signature']);
        if (!$decodedSignature) {
            Log::error('Failed to decode base64 signature.');
            return false;
        }

        $signature = $this->convertSignatureToDER($decodedSignature);

        if (!$signature) {
            Log::error('Signature conversion failed.');
            return false;
        }

        $dataToVerify = $decodedPayload['header'] . '.' . $decodedPayload['payload'];

        $verificationResult = openssl_verify($dataToVerify, $signature, $publicKey, OPENSSL_ALGO_SHA256);

        if ($verificationResult === 1) {
            return true;
        } elseif ($verificationResult === 0) {
            Log::error('Apple signature verification failed.');
            return false;
        } else {
            Log::error('Error verifying Apple signature: ' . openssl_error_string());
            return false;
        }
    }

    private function convertSignatureToDER(string $signature): string
    {
        if (strlen($signature) % 2 !== 0) {
            Log::error('Invalid signature length: ' . strlen($signature));
            return false;
        }

        $len = strlen($signature) / 2;
        $r = substr($signature, 0, $len);
        $s = substr($signature, $len);

        if (!$r || !$s) {
            Log::error('Invalid signature components (r or s missing)');
            return false;
        }


        $r = ltrim($r, "\x00");
        $s = ltrim($s, "\x00");

        if (strlen($r) > 0 && ord($r[0]) > 0x7f) {
            $r = "\x00" . $r;
        }
        if (strlen($s) > 0 && ord($s[0]) > 0x7f) {
            $s = "\x00" . $s;
        }

        return "\x30" . chr(strlen($r) + strlen($s) + 4) .
            "\x02" . chr(strlen($r)) . $r .
            "\x02" . chr(strlen($s)) . $s;
    }

    private function forwardToDevServer(Request $request)
    {
        try {

            $response = Http::post('https://dev.domain.com/route/path', $request->all());

            if ($response->successful()) {
                Log::info('Forwarded Apple notification to DEV server', [
                    'response' => $response->json()
                ]);
                return response()->json(['message' => 'Purchase processed successfully'], 200);
            } else {
                Log::error('Failed to forward Apple notification', [
                    'error' => $response->body(),
                    'status' => $response->status()
                ]);
                return response()->json(['message' => 'Failed to forward request'], 422);
            }
        } catch (Exception $e) {
            Log::error('Failed to forward Apple notification', ['error' => $e->getMessage()]);
            return response()->json(['message' => 'Failed to forward request'], 422);
        }
    }
}
