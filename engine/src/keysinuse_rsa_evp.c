#include "keysinuse_rsa_evp.h"
#include "keysinuse_rsa.h"
#include "logging.h"

#include <openssl/rsa.h>
#include <openssl/engine.h>

static int keysinuse_evp_nids[] = {
    EVP_PKEY_RSA,
    EVP_PKEY_RSA_PSS};
const int evp_nids_count = sizeof(keysinuse_evp_nids) / sizeof(keysinuse_evp_nids[0]);

static CRYPTO_ONCE once = CRYPTO_ONCE_STATIC_INIT;

static PFN_PKEY_RSA_sign default_pkey_rsa_sign = NULL;
static PFN_PKEY_RSA_sign default_pkey_rsa_pss_sign = NULL;

static EVP_PKEY_METHOD *keysinuse_pkey_rsa_meth = NULL;
static EVP_PKEY_METHOD *keysinuse_pkey_rsa_pss_meth = NULL;

static void init_internal()
{
    PFN_PKEY_RSA_init psign_init;
    int flags = EVP_PKEY_FLAG_AUTOARGLEN;
    const EVP_PKEY_METHOD *default_pkey_rsa_meth = get_default_pkey_method(EVP_PKEY_RSA);

    keysinuse_pkey_rsa_meth = EVP_PKEY_meth_new(EVP_PKEY_RSA, flags);
    if (keysinuse_pkey_rsa_meth == NULL || default_pkey_rsa_meth == NULL)
    {
        log_error("Failed to setup RSA PKEY method");
        return;
    }

    EVP_PKEY_meth_copy(keysinuse_pkey_rsa_meth, default_pkey_rsa_meth);
    EVP_PKEY_meth_get_sign(keysinuse_pkey_rsa_meth, &psign_init, &default_pkey_rsa_sign);
    EVP_PKEY_meth_set_sign(keysinuse_pkey_rsa_meth, psign_init, keysinuse_pkey_rsa_sign);

    const EVP_PKEY_METHOD *default_pkey_rsa_pss_meth = get_default_pkey_method(EVP_PKEY_RSA_PSS);
    psign_init = NULL;
    keysinuse_pkey_rsa_pss_meth = EVP_PKEY_meth_new(EVP_PKEY_RSA_PSS, flags);
    if (keysinuse_pkey_rsa_pss_meth == NULL || default_pkey_rsa_pss_meth == NULL)
    {
        log_error("Failed to setup RSA PSS PKEY method");
        return;
    }

    EVP_PKEY_meth_copy(keysinuse_pkey_rsa_pss_meth, default_pkey_rsa_pss_meth);
    EVP_PKEY_meth_get_sign(keysinuse_pkey_rsa_pss_meth, &psign_init, &default_pkey_rsa_pss_sign);
    EVP_PKEY_meth_set_sign(keysinuse_pkey_rsa_pss_meth, psign_init, keysinuse_pkey_rsa_pss_sign);
    return;
}

int init_keysinuse_pkey_methods()
{
    return CRYPTO_THREAD_run_once(&once, init_internal) &&
           keysinuse_pkey_rsa_meth != NULL &&
           keysinuse_pkey_rsa_pss_meth != NULL &&
           default_pkey_rsa_sign != NULL &&
           default_pkey_rsa_pss_sign != NULL;
}

const EVP_PKEY_METHOD *get_default_pkey_method(int nid)
{
    ENGINE *default_pkey_engine = ENGINE_get_pkey_meth_engine(nid);
    if (default_pkey_engine != NULL)
    {
        // Get EVP_PKEY_METHOD from default engine supporting nid
        return ENGINE_get_pkey_meth(default_pkey_engine, nid);
    }
    else
    {
        // No engine configured to handle this nid
        return EVP_PKEY_meth_find(nid);
    }
}

int keysinuse_pkey_methods(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid)
{
    int success = 0;

    if (pmeth == NULL || nid == 0)
    {
        *nids = keysinuse_evp_nids;
        return evp_nids_count;
    }

    switch (nid)
    {
    case EVP_PKEY_RSA:
        success = get_PKEY_RSA_meth(pmeth);
        break;
    case EVP_PKEY_RSA_PSS:
        success = get_PKEY_RSA_PSS_meth(pmeth);
        break;
    default:
        *pmeth = NULL;
        break;
    }
    return success;
}

int keysinuse_destroy_pkey_methods()
{
    keysinuse_pkey_rsa_meth = NULL;
    keysinuse_pkey_rsa_pss_meth = NULL;
}

static int on_rsa_evp_key_used(PFN_PKEY_RSA_sign passthrough_rsa_sign, EVP_PKEY_CTX *ctx,
                                unsigned char *sig, size_t *siglen,
                                const unsigned char *tbs, size_t tbslen)
{
    keysinuse_info *info = NULL;
    EVP_PKEY *pkey_rsa = EVP_PKEY_CTX_get0_pkey(ctx);
    RSA *rsa = EVP_PKEY_get0_RSA(pkey_rsa);

    // Key usage operation was counted in the EVP layer. Ensure
    // lower level API doesn't double count the signing operation.
    if (get_RSA_keysinuse_info(rsa, &info))
    {
        if (sig != NULL)
        {
            on_rsa_key_used(rsa, KEY_USE_ENCRYPT);
        }
        // There's an acceptable race condition here. Any operations using
        // the same key will not trigger a key usage increment, but the
        // operation will succeed. Same problem as keysinuse_rsa_sign
        info->disabled = 1;
    }

    int success = passthrough_rsa_sign(ctx, sig, siglen, tbs, tbslen);

    if (info != NULL)
    {
        info->disabled = 0;
    }

    return success;
}

int get_PKEY_RSA_meth(EVP_PKEY_METHOD **pkey_rsa_meth)
{
    if (pkey_rsa_meth == NULL || keysinuse_pkey_rsa_meth == NULL)
    {
        return 0;
    }
    *pkey_rsa_meth = keysinuse_pkey_rsa_meth;
    return 1;
}

static int keysinuse_pkey_rsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                               const unsigned char *tbs, size_t tbslen)
{
    return on_rsa_evp_key_used(default_pkey_rsa_sign, ctx, sig, siglen, tbs, tbslen);
}

int get_PKEY_RSA_PSS_meth(EVP_PKEY_METHOD **pkey_rsa_pss_meth)
{
    if (pkey_rsa_pss_meth == NULL || keysinuse_pkey_rsa_pss_meth == NULL)
    {
        return 0;
    }
    *pkey_rsa_pss_meth = keysinuse_pkey_rsa_pss_meth;
    return 1;
}

static int keysinuse_pkey_rsa_pss_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                                   const unsigned char *tbs, size_t tbslen)
{
    return on_rsa_evp_key_used(default_pkey_rsa_pss_sign, ctx, sig, siglen, tbs, tbslen);
}