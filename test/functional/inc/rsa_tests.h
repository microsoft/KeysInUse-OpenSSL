#pragma once

#include "functional_test.h"
#include "keys.h"

#include <cstring>
#include <memory>
#include <openssl/bio.h>

class RsaTests : functional_test
{
private:
    // Number of times to repeat operations in memory usage test
    int m_memoryIterations;
    // Number of KB used to consider the memory tests failing
    long m_kbToFailMemoryTest;
    std::shared_ptr<BIO> rsaBio;
    void Cleanup();

public:
    RsaTests(const char *logLocation, int memoryIterations = 100000, long kbToFailMemoryTest = 100) :
        functional_test(logLocation),
        m_memoryIterations(memoryIterations),
        m_kbToFailMemoryTest(kbToFailMemoryTest)
    {}
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
    bool TestMemory();
};