#ifndef KEYSINUSE_EC_H
#define KEYSINUSE_EC_H

#include <openssl/ec.h>

#include "common.h"

typedef int (*PFN_EC_meth_keygen)(EC_KEY *eckey);

typedef int (*PFN_EC_meth_sign)(int type, const unsigned char *dgst,
                                int dlen, unsigned char *sig,
                                unsigned int *siglen,
                                const BIGNUM *kinv, const BIGNUM *r,
                                EC_KEY *eckey);

typedef int (*PFN_EC_meth_sign_setup)(EC_KEY *eckey, BN_CTX *ctx_in,
                                      BIGNUM **kinvp, BIGNUM **rp);

typedef ECDSA_SIG *(*PFN_EC_meth_sign_sig)(const unsigned char *dgst,
                                           int dgst_len,
                                           const BIGNUM *in_kinv,
                                           const BIGNUM *in_r,
                                           EC_KEY *eckey);

typedef int (*PFN_EC_meth_verify)(int type, const unsigned char *dgst,
                                  int dlen, const unsigned char *sigbuf,
                                  int sig_len, EC_KEY *eckey);

typedef int (*PFN_EC_meth_verify_sig)(const unsigned char *dgst,
                                      int dgst_len,
                                      const ECDSA_SIG *sig,
                                      EC_KEY *eckey);

int get_EC_meth(EC_KEY_METHOD **ec_meth);
static void ec_index_new_key(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                             int idx, long argl, void *argp);
static void ec_index_free_key(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                              int idx, long argl, void *argp);
static int get_ec_key_identifier(EC_KEY *eckey, keysinuse_info *info);
static void on_ec_key_used(EC_KEY *eckey, unsigned int usage);

// EC_KEY_METH implementations
int keysinuse_ec_keygen(EC_KEY *eckey);

int keysinuse_ec_sign(int type, const unsigned char *dgst,
                  int dlen, unsigned char *sig,
                  unsigned int *siglen,
                  const BIGNUM *kinv, const BIGNUM *r,
                  EC_KEY *eckey);

int keysinuse_ec_verify(int type, const unsigned char *dgst,
                    int dlen, const unsigned char *sigbuf,
                    int sig_len, EC_KEY *eckey);

#endif // KEYSINUSE_EC_H