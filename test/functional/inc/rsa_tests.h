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
    RsaTests(const char *logLocation) : functional_test(logLocation) {}
    ~RsaTests()
    {
        Cleanup();
    }
    static bool IsConfigured();
    bool Setup();
    bool KeyLifecycle();
    bool PrivateEncrypt();
    bool PrivateDecrypt();
    bool SignVerify();
    bool EventThrottling();
};