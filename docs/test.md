# Test

All testing related files can be found in the `/test` folder. These include the source code for the functional, unit, and latency tests, and dummy certificates for manual testing. The functional and unit tests are written using a simple test framework found in `/test/common`. This can be replaced with a different testing framework at any time, but migrating to an existing framework has not been planned or found necessary.

# Functional Tests
The functional tests test the correct behavior of the keysinuse engine when it has been installed and configured as the default OpenSSL engine. They are intended to verify the correct logging, throttling, and passthrough behavior of the engine.

| OpenSSL API set | Test Case | Description |
| --- | --- | --- |
| N/A | Setup | Ensures the keysinuse engine can be loaded via the config and sets the logging ID for the tests
| RSA | Configuration | Ensures the keysinuse engine is the default for RSA operations. Performs test related initialization |
| RSA | Private Encrypt | Encrypts a random blob with the RSA private key (`RSA_private_encrypt`). Ensures the data can be decrypted using the public key (`RSA_public_decrypt`), and an event is logged by the engine with 1 encrypt/sign operation |
| RSA | Private Decrypt | Encrypts a random blob with the RSA public key (`RSA_public_encrypt`). Ensures the data can be decrypted using the private key (`RSA_public_encrypt`), and an event is logged by the engine with 1 decrypt operation |
| RSA | Sign/Verify | Signs a random blob of data with the RSA private key (`RSA_sign`). Ensures that the data can be verified usign the RSA public key (`RSA_verify`), and that an event is logged by the engine with 1 encrypt/sign operation |
| RSA | Events Throttled | Ensures that the engine properly throttles RSA key use events. Encrypts twice with the private key, then decrypts onece with the same key. Ensures that only the first encrypt is logged. Destroys the RSA key object and ensures the second encrypt and decrypt are logged in one following event |
| EC_KEY | Configuration | Ensures the keysinuse engine is the default for EC_KEY operations. Performs test related initialization |
| EC_KEY | Sign/Verify | Signs a random blob of data with the EC private key (`ECDSA_sign`). Ensures that the data can be verified usign the EC public key (`ECDSA_verify`), and that an event is logged by the engine with 1 encrypt/sign operation |
| EC_KEY | Events Throttled | Ensures that the engine properly throttles EC key use events. Signs twice with the private key. Ensures that only the first sign is logged. Destroys the EC key object and ensures the second sign and decrypt is logged|
| EVP_PKEY | Configuration | Ensures the keysinuse engine is the default for EVP_PKEY operations using RSA and RSA PSS keys. Performs test related initialization |
| EVP_PKEY  | Sign/Verify (RSA key) | Signs a random blob with the RSA private key (`EVP_DigestSign`). Ensures the data can be verified using the public key (`EVP_DigestVerify`), and that an event is logged by the engine with 1 encrypt/sign operation  |
| EVP_PKEY  | Sign/Verify (RSA PSS key) | Signs a random blob with the RSA PSS private key (`EVP_DigestSign`). Ensures the data can be verified using the public key (`EVP_DigestVerify`), and that an event is logged by the engine with 1 encrypt/sign operation   |
| EVP_PKEY  | Encrypt/Decrypt (RSA key) | Encrypts a random blob with the RSA public key (`EVP_PKEY_encrypt`). Ensures the data can be decrypted using the private key (`EVP_PKEY_decrypt`), and an event is logged by the engine with 1 decrypt operation |
| EVP_PKEY  | Events Throttled (RSA key) | Ensures that the engine properly throttles RSA and RSA PSS key use events. Encrypts twice with the private key. Ensures that only the first encrypt is logged. Destroys the key object and ensures the second encrypt and decrypt are logged in one following event. The test is performed for RSA, then RSA PSS keys |

# Unit Tests
The majority of the keysinuse code is written as passthrough logic for the OpenSSL engine framework. Unit tests for most functions would require mocking and has not been done yet. Currently, the unit tests are limited to helper functions internal to the engine.

| Source File | Function | Description
| --- | --- | --- |
| common.h | `global_logging_disabled` | Ensures the function returns true by default, and returns false when the logging backoff is less than zero |
| common.h | `new_keysinuse_info` | Ensures the keysinuse info struct, which is saved to private keys as custom data, is allocated and zeroed correctly by the function |
| common.h | `should_log` | Ensures the function returns true only when the conditions are met to log. Tests the behavior by modifying the logging backoff, waiting for the logging backoff time to expire, and verifying the timestamps returned by the function |
| common.h | `generate_key_id` | Ensures the key id derived by this function exactly matches the first 16 bytes of the SHA256 hash of the public key.
| logging.h | `log_notice` | Ensures the message passed to this function is correctly written to the expected location, with formatting preserved and the expected header prepended |
| logging.h | `log_error` | Ensures the message passed to this function is correctly written to the expected location, with formatting preserved and the expected header prepended |

# Latency Tests
The latency tests are intended to be a simple benchmark, to test the overhead introduced by the keysinuse engine. They accept the number of encryptions to run for averaging. The tests encrypt a random 32 byte blob *n* number of times, and average the result.

First, the same instance of the key object is used for all *n* encrypts. This tests the performance for a long lived key object, where throttling will occur. Then, the key object is reloaded each time for all *n* encrypts. This tests the performance of short lived key objects, where throttling would not occur, and an event is written every time.

The time taken is separated by user mode, system mode, and overall. The time is averaged for *n* operations and printed in milliseconds. The tests use the default engine, and the user is expected to install the keysinuse engine before running, if they which to benchmark performance with the engine.

# Manual Testing
The certificates in `/test/certs` can be used for manual testing with existing applications such as nginx, apache, and curl.

| Certificate/Key Name | Key ID |
| --- | --- |
| eccplayclient | 8aa8019a66ed73d205a23b6c8840ca9e |
| eccplayserver | 11bc39316e349284074df02007f96d12 |
| playclient | b9f99b1a9683d4de53ecdde9b3b4b4ce |
| playserver | 386bef5d701d7669fa87a7ec9af2da46 |