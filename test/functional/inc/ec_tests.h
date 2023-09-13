#pragma once

#include "functional_test.h"
#include "keys.h"

#include <cstring>
#include <memory>
#include <openssl/bio.h>

class EcTests : functional_test
{
private:
    // Number of times to repeat operations in memory usage test
    int m_memoryIterations;
    // Number of KB used to consider the memory tests failing
    long m_kbToFailMemoryTest;
    std::shared_ptr<BIO> ecBio;
    void Cleanup();

public:
    EcTests(const char *logLocation, int memoryIterations = 100000, long kbToFailMemoryTest = 100) :
        functional_test(logLocation),
        m_memoryIterations(memoryIterations),
        m_kbToFailMemoryTest(kbToFailMemoryTest)
    {}
    ~EcTests()
    {
        Cleanup();
    }

    static bool IsConfigured();
    bool Setup();
    bool KeyLifecycle();
    bool SignVerify();
    bool EventThrottling();
    bool TestMemory();
};