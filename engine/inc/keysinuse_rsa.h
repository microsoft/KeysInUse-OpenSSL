#ifndef KEYSINUSE_RSA_H
#define KEYSINUSE_RSA_H

#include <openssl/rsa.h>

#include "common.h"

typedef int (*PFN_RSA_encrypt_decrypt)(int flen, const unsigned char *from, unsigned char *to,
                                       RSA *rsa, int padding);
typedef int (*PFN_RSA_sign_verify)(int type, const unsigned char *m, unsigned int m_len,
                   unsigned char *sigret, unsigned int *siglen, const RSA *rsa);

int get_RSA_meth(RSA_METHOD **rsa_meth);
static void rsa_index_new_key(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                              int idx, long argl, void *argp);
static void rsa_index_free_key(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                               int idx, long argl, void *argp);
static int get_rsa_key_identifier(RSA *rsa, keysinuse_info *info);
int get_RSA_keysinuse_info(RSA* rsa, keysinuse_info **info);
void on_rsa_key_used(RSA *rsa, unsigned int usage);

// RSA_meth implementations
int keysinuse_rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to,
                      RSA *rsa, int padding);
int keysinuse_rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to,
                      RSA *rsa, int padding);
int keysinuse_rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to,
                       RSA *rsa, int padding);
int keysinuse_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to,
                       RSA *rsa, int padding);
int keysinuse_rsa_sign(int type, const unsigned char *m, unsigned int m_len,
                   unsigned char *sigret, unsigned int *siglen, const RSA *rsa);


#endif // KEYSINUSE_RSA_H