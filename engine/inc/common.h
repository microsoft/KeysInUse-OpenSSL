#ifndef COMMON_H
#define COMMON_H

#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <time.h>
// Logged key id is the first 16 bytes of the SHA-256 hash, represented as a hex string
#define TRUNCATED_DIGEST_LENGTH (SHA256_DIGEST_LENGTH / 2)
#define KEY_IDENTIFIER_CHAR_SIZE (TRUNCATED_DIGEST_LENGTH * 2 + 1)
#define DEFAULT_LOGGING_BACKOFF 60 * 60

// Key usage flags
#define KEY_USE_ENCRYPT 1
#define KEY_USE_DECRYPT 2

// keysinuse_info struct is saved to each key instance to track
// state across uses.
typedef struct
{
    int disabled;
    time_t first_use;
    time_t last_logged_use;
    unsigned int encrypts;
    unsigned int decrypts;
    char key_identifier[KEY_IDENTIFIER_CHAR_SIZE];
    CRYPTO_RWLOCK *lock;
} keysinuse_info;

static long logging_backoff;

void set_logging_backoff(long new_backoff);
int global_logging_disabled();

keysinuse_info *new_keysinuse_info();
int should_log(keysinuse_info *info);
int generate_key_id(unsigned char *der, size_t size, char key_identifier[KEY_IDENTIFIER_CHAR_SIZE]);

#endif // COMMON_H