#pragma once

#include "functional_test.h"
#include "keys.h"

#include <cstring>
#include <memory>
#include <openssl/bio.h>

class RsaTests : functional_test
{
private:
    std::shared_ptr<BIO> rsaBio;
    void Cleanup();

public:
    RsaTests(const char *logLocation) : functional_test(logLocation),
                                        rsaBio(
                                            BIO_new_mem_buf((void *)rsa_keypair, -1),
                                            BIO_free) {}
    ~RsaTests()
    {
        Cleanup();
    }
    bool IsConfigured();
    bool PrivateEncrypt();
    bool PrivateDecrypt();
    bool SignVerify();
    bool EventThrottling();
};