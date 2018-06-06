# jwt-http-client-script

This is a dev tool.

It's JWT signer for HTTP requests.

It loads a KID from environment (which identifies the target API consumer), and a private RSA key (PKCS#8 format) from disk
(used to sign the JWT). The private RSA key location is informed through PRIVATE_KEY_FILENAME environment variable.

The JWT currently sends two claims: IAT, and path (this is the target API endpoint path).
