#include "keysinuse_rsa.h"
#include "logging.h"

#include <string.h>
#include <openssl/err.h>

static int rsa_keysinuse_info_index = -1;

int get_RSA_meth(RSA_METHOD **rsa_meth)
{
    if (rsa_meth == NULL)
    {
        return 0;
    }
    *rsa_meth = RSA_meth_dup(RSA_get_default_method());

    if (rsa_keysinuse_info_index == -1)
    {
        rsa_keysinuse_info_index = RSA_get_ex_new_index(0, NULL, rsa_index_new_key, NULL, rsa_index_free_key);
    }

    int set_sign_success = 1;
    const RSA_METHOD *ossl_rsa_meth = RSA_get_default_method();
    if (RSA_meth_get_sign(ossl_rsa_meth) != NULL)
    {
        set_sign_success = RSA_meth_set_sign(*rsa_meth, keysinuse_rsa_sign);
    }

    return set_sign_success &&
           RSA_meth_set_priv_dec(*rsa_meth, keysinuse_rsa_priv_dec) &&
           RSA_meth_set_priv_enc(*rsa_meth, keysinuse_rsa_priv_enc);
}

static void rsa_index_new_key(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                              int idx, long argl, void *argp)
{
    RSA *rsa = (RSA *)parent;
    keysinuse_info *info = new_keysinuse_info();
    RSA_set_ex_data(rsa, rsa_keysinuse_info_index, info);
}

static void rsa_index_free_key(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                               int idx, long argl, void *argp)
{
    RSA *rsa = (RSA *)parent;
    keysinuse_info *info = (keysinuse_info *)ptr;

    if (info != NULL)
    {
        if (!global_logging_disabled() &&
            (info->encrypts > 0 || info->decrypts > 0) &&
            (info->key_identifier[0] != '\0' || get_rsa_key_identifier(rsa, info)))
        {
            log_notice("%s,%d,%d,%ld,%ld",
                    info->key_identifier,
                    info->encrypts,
                    info->decrypts,
                    info->first_use,
                    time(NULL));
        }

        CRYPTO_THREAD_lock_free(info->lock);
        OPENSSL_free(info);
    }

    if (rsa != NULL)
    {
        RSA_set_ex_data(rsa, rsa_keysinuse_info_index, NULL);
    }
}

static int get_rsa_key_identifier(RSA *rsa, keysinuse_info *info)
{
    if (rsa == NULL)
        return 0;

    int ret = 1;
    unsigned char *key_buf = NULL,
                  *key_buf_start = NULL;

    size_t size = i2d_RSAPublicKey(rsa, NULL);
    if (size < 0)
    {
        log_error("Failed to get key size,OPENSSL_%ld",ERR_get_error());
        ret = 0;
        goto end;
    }

    key_buf_start = OPENSSL_malloc(size);
    if (!key_buf_start)
    {
        log_error("Failed to allocate space for DER encoded RSA key,OPENSSL_%ld",ERR_get_error());
        ret = 0;
        goto end;
    }

    key_buf = key_buf_start;

    if (!i2d_RSAPublicKey(rsa, &key_buf))
    {
        log_error("Failed to encode key,OPENSSL_%ld",ERR_get_error());
        ret = 0;
        goto end;
    }

    // i2d_RSAPublicKey moves key_buf pointer to the end of the buffer
    if (key_buf != key_buf_start + size)
    {
        log_error("Key encoded with unexpected size");
        ret = 0;
        goto end;
    }

    if (!generate_key_id(key_buf_start, size, info->key_identifier))
    {
        ret = 0;
        goto end;
    }
end:
    OPENSSL_free(key_buf_start);
    return ret;
}

int get_RSA_keysinuse_info(RSA* rsa, keysinuse_info **info)
{
    if (rsa_keysinuse_info_index == -1)
    {
        log_error("keysinuse info index not initialized");
        return 0;
    }

    *info = RSA_get_ex_data(rsa, rsa_keysinuse_info_index);
    if (*info == NULL)
    {
        log_error("Failed to retrieve keysinuse info from key,OPENSSL_%ld",ERR_get_error());
        return 0;
    }

    return 1;
}

void on_rsa_key_used(RSA *rsa, unsigned int usage)
{
    if (global_logging_disabled())
        return;

    int can_log = 0;
    keysinuse_info tmp_info;
    keysinuse_info *info = NULL;

    if (!get_RSA_keysinuse_info(rsa, &info))
    {
        return;
    }

    if (info->disabled)
        return;

    CRYPTO_THREAD_write_lock(info->lock);

    switch (usage)
    {
    case KEY_USE_ENCRYPT:
        info->encrypts++;
        break;
    case KEY_USE_DECRYPT:
        info->decrypts++;
        break;
    }

    if (should_log(info))
    {
        time_t now = time(NULL);
        if (info->first_use == 0)
        {
            info->first_use = now;
        }

        if (info->key_identifier[0] != 0 ||
            get_rsa_key_identifier(rsa, info))
        {
            memcpy(&tmp_info, info, sizeof(keysinuse_info));
            tmp_info.last_logged_use = now;
            can_log = 1;
            info->first_use = now;
            info->encrypts = 0;
            info->decrypts = 0;
        }
    }
    CRYPTO_THREAD_unlock(info->lock);

    if (can_log)
    {
        log_notice("%s,%d,%d,%ld,%ld",
                   tmp_info.key_identifier,
                   tmp_info.encrypts,
                   tmp_info.decrypts,
                   tmp_info.first_use,
                   tmp_info.last_logged_use);
    }
}

int keysinuse_rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to,
                      RSA *rsa, int padding)
{
    on_rsa_key_used(rsa, KEY_USE_DECRYPT);

    const RSA_METHOD *ossl_rsa_meth = RSA_get_default_method();
    PFN_RSA_encrypt_decrypt pfn_rsa_meth_pub_dec = RSA_meth_get_pub_dec(ossl_rsa_meth);
    if (!pfn_rsa_meth_pub_dec)
        return 0;
    return pfn_rsa_meth_pub_dec(flen, from, to, rsa, padding);
}

int keysinuse_rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to,
                      RSA *rsa, int padding)
{
    on_rsa_key_used(rsa, KEY_USE_ENCRYPT);

    const RSA_METHOD *ossl_rsa_meth = RSA_get_default_method();
    PFN_RSA_encrypt_decrypt pfn_rsa_meth_pub_enc = RSA_meth_get_pub_enc(ossl_rsa_meth);
    if (!pfn_rsa_meth_pub_enc)
    {
        return 0;
    }
    return pfn_rsa_meth_pub_enc(flen, from, to, rsa, padding);
}

int keysinuse_rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to,
                       RSA *rsa, int padding)
{
    on_rsa_key_used(rsa, KEY_USE_DECRYPT);

    const RSA_METHOD *ossl_rsa_meth = RSA_get_default_method();
    PFN_RSA_encrypt_decrypt pfn_rsa_meth_priv_dec = RSA_meth_get_priv_dec(ossl_rsa_meth);
    if (!pfn_rsa_meth_priv_dec)
    {
        return 0;
    }
    return pfn_rsa_meth_priv_dec(flen, from, to, rsa, padding);
}

int keysinuse_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to,
                       RSA *rsa, int padding)
{
    on_rsa_key_used(rsa, KEY_USE_ENCRYPT);

    const RSA_METHOD *ossl_rsa_meth = RSA_get_default_method();
    PFN_RSA_encrypt_decrypt pfn_rsa_meth_priv_enc = RSA_meth_get_priv_enc(ossl_rsa_meth);
    if (!pfn_rsa_meth_priv_enc)
        return 0;
    return pfn_rsa_meth_priv_enc(flen, from, to, rsa, padding);
}

int keysinuse_rsa_sign(int type, const unsigned char *m, unsigned int m_len,
                   unsigned char *sigret, unsigned int *siglen, const RSA *rsa)
{
    const RSA_METHOD* rsa_meth = RSA_get_method(rsa);
    RSA_METHOD* passthrough_rsa_meth = (RSA_METHOD*)RSA_get_default_method();

    PFN_RSA_sign_verify cur_rsa_sign = RSA_meth_get_sign(rsa_meth);
    PFN_RSA_sign_verify passthrough_rsa_sign = NULL;

    if (passthrough_rsa_meth != NULL &&
        passthrough_rsa_meth != rsa_meth)
    {
        passthrough_rsa_sign = RSA_meth_get_sign(passthrough_rsa_meth);;
    }

    if (passthrough_rsa_sign != NULL)
    {
        on_rsa_key_used((RSA*)rsa, KEY_USE_ENCRYPT);
    }

    /*
    If passthrough_rsa_sign doesn't support rsa_sign, including the
    default software implementation, RSA_sign will perform the padding
    and passthrough to rsa_private_encrypt. We need to go through
    RSA_sign in case passthrough_rsa_sign doesn't implement rsa_sign

    There's an acceptable race condition due to this. If the rsa_sign
    function has been updated in rsa_meth's table, any new calls to
    RSA_sign will go to passthrough_rsa_sign instead of this function.
    The operation will succeed, but the key use won't be tracked.
    */
    RSA_meth_set_sign((RSA_METHOD*)rsa_meth, passthrough_rsa_sign);
    int ret = RSA_sign(type, m, m_len, sigret, siglen, (RSA*)rsa);
    RSA_meth_set_sign((RSA_METHOD*)rsa_meth, cur_rsa_sign);

    return ret;
}