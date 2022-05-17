#pragma once

#include "functional_test.h"
#include "keys.h"

#include <cstring>
#include <memory>
#include <openssl/bio.h>

class EcTests : functional_test
{
private:
    std::shared_ptr<BIO> ecBio;
    void Cleanup();

public:
    EcTests(const char *logLocation) : functional_test(logLocation),
                                       ecBio(
                                           BIO_new_mem_buf((void *)ec_keypair, -1),
                                           BIO_free) {}
    ~EcTests()
    {
        Cleanup();
    }
    bool IsConfigured();
    bool SignVerify();
    bool EventThrottling();
};