#include "common.h"

#include "logging.h"

#include <stdlib.h>
#include <stdio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>

static long logging_backoff = DEFAULT_LOGGING_BACKOFF;

void set_logging_backoff(long new_backoff)
{
    logging_backoff = new_backoff;
}

// Set logging backoff to something negative to disable logging
int global_logging_disabled()
{
    return logging_backoff <= 0;
}

keysinuse_info *new_keysinuse_info()
{
    keysinuse_info *info = OPENSSL_zalloc(sizeof(keysinuse_info));
    info->key_identifier[0] = '\0';
    info->lock = CRYPTO_THREAD_lock_new();
    return info;
}

int should_log(keysinuse_info *info)
{
    if (global_logging_disabled()) return 0;

    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
    {
        log_error("Failed to get current clock time,SYS_%d", errno);
        return 0;
    }

    if (info->last_logged_use > 0 &&
        (now.tv_sec - info->last_logged_use) < logging_backoff)
    {
        return 0;
    }

    info->last_logged_use = now.tv_sec;

    return 1;
}

int generate_key_id(unsigned char *der, size_t size, char key_identifier[KEY_IDENTIFIER_CHAR_SIZE])
{
    char *tmp_key_identifier = key_identifier;
    unsigned int hash_size;
    unsigned char hash_bytes[SHA256_DIGEST_LENGTH];
    unsigned char *hash_bytes_ptr = &hash_bytes[0];

    if (!EVP_Digest(der, size, hash_bytes, &hash_size, EVP_sha256(), NULL) ||
        hash_size != SHA256_DIGEST_LENGTH)
    {
        log_error("Failed to hash encoded key,OPENSSL_%ld", ERR_get_error());
        return 0;
    }

    // Don't need the entire hash to uniquely identify key.
    for (int i = 0; i < TRUNCATED_DIGEST_LENGTH; i++)
    {
        int b = (*hash_bytes_ptr & 0xF0) >> 4;
        *tmp_key_identifier++ = (char)((b <= 9) ? b + L'0' : (b - 10) + L'a');
        b = *hash_bytes_ptr & 0x0F;
        *tmp_key_identifier++ = (char)((b <= 9) ? b + L'0' : (b - 10) + L'a');
        hash_bytes_ptr++;
    }
    *tmp_key_identifier++ = 0;

    return 1;
}