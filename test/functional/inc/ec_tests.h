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
    EcTests(const char *logLocation) : functional_test(logLocation) {}
    ~EcTests()
    {
        Cleanup();
    }

    static bool IsConfigured();
    bool Setup();
    bool SignVerify();
    bool EventThrottling();
};