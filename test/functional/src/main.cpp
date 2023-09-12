#include "test.h"
#include "ec_tests.h"
#include "evp_tests.h"
#include "rsa_tests.h"

#include <keysinuse_engine.h>
#include "logging.h"

#include <iostream>

using namespace std;

const char *logging_id = "functionaltest";

int mem_leaks_cb(const char *str, size_t len, void *u)
{
    TestFail(str);
    return 1;
}

int main(int argc, char **argv)
{
    bool isRsaConfigured = false;
    bool isEcConfigured  = false;
    bool isEvpConfigured = false;

    char logLocation[LOG_PATH_LEN + 1];
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    // Call OPENSSL_init_crypto to force config file load
    RunTest("== Setup ==", [&]()
    {
        unsigned long init_opts = OPENSSL_INIT_ENGINE_DYNAMIC;

        if (argc < 2)
        {
            init_opts |= OPENSSL_INIT_LOAD_CONFIG;
        }

        if (!OPENSSL_init_crypto(init_opts, NULL))
        {
            TestFailOpenSSLError("OPENSSL_init_crypto failed");
            TestFinish();
        }

        // Manually load engine. This does not verify default global configuration
        if (argc >= 2) {
            if (!OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_DYNAMIC, NULL))
            {
                TestFailOpenSSLError("OPENSSL_init_crypto failed");
                TestFinish();
            }
            shared_ptr<ENGINE> dynamicEngine(
                ENGINE_by_id("dynamic"),
                ENGINE_free);

            if (dynamicEngine == nullptr)
            {
                TestFailOpenSSLError("Failed to load dynamic engine");
                TestFinish();
            }

            if (!ENGINE_ctrl_cmd_string(dynamicEngine.get(), "SO_PATH", argv[1], 0))
            {
                TestFailOpenSSLError("Failed to set path for dynamically loaded engine");
                TestFinish();
            }

            if (!ENGINE_ctrl_cmd_string(dynamicEngine.get(), "LOAD", NULL, 0))
            {
                TestFailOpenSSLError("Failed to load engine from dynamic path");
                TestFinish();
            }

            if (!ENGINE_init(dynamicEngine.get()))
            {
                TestFailOpenSSLError("Failed to initialize engine from dynamic path");
                TestFinish();
            }

            if (!ENGINE_add(dynamicEngine.get()))
            {
                TestFailOpenSSLError("Failed to add engine from dynamic path");
                TestFinish();
            }

            cout << "\33[33mLoaded engine [" << ENGINE_get_id(dynamicEngine.get()) << "] dynamically. Default configuration not tested" << endl;
        }

        return true;
    });

    RunTest("== RSA Configuration ==", [&isRsaConfigured](){return (isRsaConfigured = RsaTests::IsConfigured());});
    RunTest("== EC Configuration ==",  [&isEcConfigured](){return (isEcConfigured = EcTests::IsConfigured());});
    RunTest("== EVP Configuration ==", [&isEvpConfigured](){return (isEvpConfigured = EvpTests::IsConfigured());});

    RunTest("== Engine Control == ", [&] () {
        // Set logging ID for tests
        shared_ptr<ENGINE> keysinuseEngine(
            ENGINE_by_id(engine_id),
            ENGINE_free);
        if (keysinuseEngine == nullptr)
        {
            TestFailOpenSSLError("Failed to load keysinuse engine by ID");
            TestFinish();
        }

        if (!ENGINE_ctrl_cmd_string(keysinuseEngine.get(), "logging_id", logging_id, 0))
        {
            TestFailOpenSSLError("Failed to set logging ID in keysinuse engine");
            TestFinish();
        }

        sprintf(logLocation, LOG_PATH_TMPL, "not", geteuid(), logging_id);
        remove(logLocation);

        return true;
    });
    // RSA APIs
    if (isRsaConfigured)
    {
        RsaTests rsaTests(logLocation);

        if (RunTest("== RSA setup ==",            std::bind(&RsaTests::Setup, &rsaTests)));
        {
            RunTest("== RSA Key Lifecycle ==",    std::bind(&RsaTests::KeyLifecycle, &rsaTests));
            RunTest("== RSA private encrypt ==",  std::bind(&RsaTests::PrivateEncrypt, &rsaTests));
            RunTest("== RSA private decrypt ==",  std::bind(&RsaTests::PrivateDecrypt, &rsaTests));
            RunTest("== RSA sign/verify ==",      std::bind(&RsaTests::SignVerify, &rsaTests));
            RunTest("== RSA events throttled ==", std::bind(&RsaTests::EventThrottling, &rsaTests));
        }
    }

    // EC_KEY APIs
    if (isEcConfigured)
    {
        EcTests ecTests(logLocation);

        if (RunTest("== EC setup ==",            std::bind(&EcTests::Setup, &ecTests)))
        {
            RunTest("== EC Key Lifecycle ==",    std::bind(&EcTests::KeyLifecycle, &ecTests));
            RunTest("== EC sign/verify ==",      std::bind(&EcTests::SignVerify, &ecTests));
            RunTest("== EC events throttled ==", std::bind(&EcTests::EventThrottling, &ecTests));
        }
    }

    // EVP APIs (RSA and RSA PSS supported)
    if (isEvpConfigured)
    {
        EvpTests evpTests(logLocation);

        if (RunTest("== EVP setup ==",            std::bind(&EvpTests::Setup, &evpTests)));
        {
            RunTest("== EVP sign/verify ==",      std::bind(&EvpTests::RSA_SignVerify, &evpTests));
            RunTest("== EVP sign/verify PSS ==",  std::bind(&EvpTests::RSA_PSS_SignVerify, &evpTests));
            RunTest("== EVP encrypt/decrypt ==",  std::bind(&EvpTests::RSA_EncryptDecrypt, &evpTests));
            RunTest("== EVP events throttled ==", std::bind(&EvpTests::EventThrottling, &evpTests));
        }
    }

#ifndef OPENSSL_NO_CRYPTO_MDEBUG
    RunTest("== Memory leaks ==", [&] () {
        return CRYPTO_mem_leaks_cb(mem_leaks_cb, NULL) == 1;
    });
#endif

    TestFinish();
}