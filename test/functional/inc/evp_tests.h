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
    EvpTests(const char *logLocation) : functional_test(logLocation) {}
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