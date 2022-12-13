#pragma once

#include "functional_test.h"
#include "keys.h"

#include <cstring>
#include <memory>
#include <openssl/bio.h>

class EvpTests : public functional_test
{
private:
    std::shared_ptr<BIO> rsaBio;
    std::shared_ptr<BIO> rsaPssBio;

    bool EvpDigestSignVerify(std::shared_ptr<EVP_PKEY> evpKeyPair);
    void Cleanup();

public:
    EvpTests(const char *logLocation) : functional_test(logLocation),
                                        rsaBio(
                                            BIO_new_mem_buf((void *)rsa_keypair, -1),
                                            BIO_free),
                                        rsaPssBio(
                                            BIO_new_mem_buf((void *)rsa_pss_keypair, -1),
                                            BIO_free) {}
    ~EvpTests()
    {
        Cleanup();
    }

    static bool IsConfigured();
    bool Setup();
    bool RSA_EncryptDecrypt();
    bool RSA_SignVerify();
    bool RSA_PSS_SignVerify();
    bool EventThrottling();
};