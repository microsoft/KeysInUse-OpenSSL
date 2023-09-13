#include "keysinuse_ec.h"
#include "logging.h"

#include <string.h>
#include <openssl/err.h>

static int ec_keysinuse_info_index = -1;

int get_EC_meth(EC_KEY_METHOD **ec_meth)
{
    if (ec_meth == NULL)
    {
        return 0;
    }

    PFN_EC_meth_sign_setup pfn_ec_sign_setup;
    PFN_EC_meth_sign_sig pfn_ec_sign_sig;

    *ec_meth = EC_KEY_METHOD_new(EC_KEY_get_default_method());

    const EC_KEY_METHOD *ossl_ec_key_meth = EC_KEY_get_default_method();

    EC_KEY_METHOD_get_sign(ossl_ec_key_meth, NULL, &pfn_ec_sign_setup, &pfn_ec_sign_sig);
    if (!pfn_ec_sign_setup || !pfn_ec_sign_sig)
    {
        log_error("Failed to get sign,OPENSSL_%ld",ERR_get_error());
        return 0;
    }

    if (ec_keysinuse_info_index == -1)
    {
        ec_keysinuse_info_index = EC_KEY_get_ex_new_index(0, NULL, ec_index_new_key, NULL, ec_index_free_key);
    }

    EC_KEY_METHOD_set_sign(*ec_meth, keysinuse_ec_sign, pfn_ec_sign_setup, pfn_ec_sign_sig);
    EC_KEY_METHOD_set_keygen(*ec_meth, keysinuse_ec_keygen);
    return 1;
}

static void ec_index_new_key(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                             int idx, long argl, void *argp)
{
    if (parent == NULL)
        return;

    EC_KEY *eckey = (EC_KEY *)parent;
    keysinuse_info *info = new_keysinuse_info();
    EC_KEY_set_ex_data(eckey, ec_keysinuse_info_index, info);
}

static void ec_index_free_key(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                              int idx, long argl, void *argp)
{
    if (parent == NULL)
        return;

    EC_KEY *eckey = (EC_KEY *)parent;
    keysinuse_info *info = (keysinuse_info *)ptr;

    if (info != NULL)
    {
        if (!global_logging_disabled() &&
            (info->encrypts > 0 || info->decrypts > 0) &&
            (info->key_identifier[0] != '\0' || get_ec_key_identifier(eckey, info)))
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

    EC_KEY_set_ex_data(eckey, ec_keysinuse_info_index, NULL);
}

static void on_ec_key_used(EC_KEY *eckey, unsigned int usage)
{
    if (global_logging_disabled() ||
        eckey == NULL)
        return;

    int can_log = 0;
    keysinuse_info tmp_info;
    keysinuse_info *info = NULL;

    if (ec_keysinuse_info_index != -1)
    {
        info = EC_KEY_get_ex_data(eckey, ec_keysinuse_info_index);
    }

    if (info == NULL)
    {
        log_error("Failed to retrieve keysinuse info from key,OPENSSL_%ld",ERR_get_error());
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
            get_ec_key_identifier(eckey, info))
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

static int get_ec_key_identifier(EC_KEY *eckey, keysinuse_info *info)
{
    if (eckey == NULL)
        return 0;

    int ret = 1;
    unsigned char *key_buf = NULL,
                  *key_buf_start = NULL;

    size_t size = i2o_ECPublicKey(eckey, NULL);
    if (size < 0)
    {
        log_error("Failed to get key size,OPENSSL_%ld",ERR_get_error());
        ret = 0;
        goto end;
    }

    key_buf_start = OPENSSL_malloc(size);
    if (!key_buf_start)
    {
        log_error("Failed to allocate space for DER encoded EC key,OPENSSL_%ld",ERR_get_error());
        ret = 0;
        goto end;
    }

    key_buf = key_buf_start;

    if (!i2o_ECPublicKey(eckey, &key_buf))
    {
        log_error("Failed to encode key,OPENSSL_%ld",ERR_get_error());
        ret = 0;
        goto end;
    }

    // i2o_ECPublicKey moves key_buf pointer to the end of the buffer
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

int keysinuse_ec_keygen(EC_KEY *eckey){
    const EC_KEY_METHOD *ossl_ec_key_meth = EC_KEY_get_default_method();

    keysinuse_info *info = NULL;

    if (eckey != NULL &&
        ec_keysinuse_info_index != -1)
    {
        info = EC_KEY_get_ex_data(eckey, ec_keysinuse_info_index);
    }

    if (info == NULL)
    {
        log_error("Failed to retrieve keysinuse info from key,OPENSSL_%ld",ERR_get_error());
    }
    else
    {
        info->disabled = 1;
    }

    PFN_EC_meth_keygen pfn_ec_meth_keygen;
    EC_KEY_METHOD_get_keygen(ossl_ec_key_meth, &pfn_ec_meth_keygen);
    if (!pfn_ec_meth_keygen)
    {
        return 0;
    }
    return pfn_ec_meth_keygen(eckey);
}

int keysinuse_ec_sign(int type, const unsigned char *dgst,
                  int dlen, unsigned char *sig,
                  unsigned int *siglen,
                  const BIGNUM *kinv, const BIGNUM *r,
                  EC_KEY *eckey)
{
    on_ec_key_used(eckey, KEY_USE_ENCRYPT);

    const EC_KEY_METHOD *ossl_ec_key_meth = EC_KEY_get_default_method();
    PFN_EC_meth_sign pfn_ec_meth_sign;
    EC_KEY_METHOD_get_sign(ossl_ec_key_meth, &pfn_ec_meth_sign, NULL, NULL);
    if (!pfn_ec_meth_sign)
    {
        return 0;
    }
    return pfn_ec_meth_sign(type, dgst, dlen, sig, siglen, kinv, r, eckey);
}

int keysinuse_ec_verify(int type, const unsigned char *dgst,
                    int dgst_len, const unsigned char *sigbuf,
                    int sig_len, EC_KEY *eckey)
{
    on_ec_key_used(eckey, KEY_USE_DECRYPT);

    const EC_KEY_METHOD *ossl_ec_key_meth = EC_KEY_get_default_method();
    PFN_EC_meth_verify pfn_ec_meth_verfify;
    EC_KEY_METHOD_get_verify(ossl_ec_key_meth, &pfn_ec_meth_verfify, NULL);
    if (!pfn_ec_meth_verfify)
    {
        return 0;
    }
    return pfn_ec_meth_verfify(type, dgst, dgst_len, sigbuf, sig_len, eckey);
}