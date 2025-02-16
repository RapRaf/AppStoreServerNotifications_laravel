## App Store Server Notifications

The `AppleNotificationController.php` file is designed to handle App Store Server Notifications validation in a Laravel application.

The JWTReader model class is a helper for decoding JWS tokens. You are free to use any libraries of your choice for this purpose.

### PHP System Dependencies

To ensure this controller functions correctly, the following PHP **extensions** must be installed:

- `php-curl` – Required for making HTTP requests.
- `php-mbstring` – Ensures proper handling of multibyte strings.
- `php-bcmath` – Used for certain cryptographic operations.
- `php-json` – Required for handling JSON data.
- `php-openssl` – Necessary for cryptographic functions (JWT verification).

#### (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install php-curl php-mbstring php-bcmath php-json php-openssl
```
