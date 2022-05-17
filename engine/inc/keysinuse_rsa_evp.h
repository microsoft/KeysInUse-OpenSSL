#ifndef KEYSINUSE_RSA_EVP_H
#define KEYSINUSE_RSA_EVP_H

#include <openssl/evp.h>

typedef int (*PFN_PKEY_RSA_init) (EVP_PKEY_CTX *ctx);
typedef int (*PFN_PKEY_RSA_sign) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                                         const unsigned char *tbs, size_t tbslen);

int init_keysinuse_pkey_methods();
const EVP_PKEY_METHOD *get_default_pkey_method(int nid);

int keysinuse_pkey_methods(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid);
int keysinuse_destroy_pkey_methods();

static int on_rsa_evp_key_used(PFN_PKEY_RSA_sign passthrough_rsa_sign, EVP_PKEY_CTX *ctx,
                                unsigned char *sig, size_t *siglen,
                                const unsigned char *tbs, size_t tbslen);

// RSA PKEY meth implementations
int get_PKEY_RSA_meth(EVP_PKEY_METHOD  **pkey_rsa_meth);
static int keysinuse_pkey_rsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                               const unsigned char *tbs, size_t tbslen);
int get_PKEY_RSA_PSS_meth(EVP_PKEY_METHOD  **pkey_rsa_pss_meth);
static int keysinuse_pkey_rsa_pss_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                                   const unsigned char *tbs, size_t tbslen);

#endif // KEYSINUSE_RSA_EVP_H