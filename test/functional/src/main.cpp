#include "test.h"
#include "ec_tests.h"
#include "evp_tests.h"
#include "rsa_tests.h"

#include <keysinuse_engine.h>
#include "logging.h"

#include <iostream>

using namespace std;

const char *logging_id = "functionaltest";

int main(int argc, char **argv)
{
    bool isRsaConfigured = false;
    bool isEcConfigured  = false;
    bool isEvpConfigured = false;

    char logLocation[LOG_PATH_LEN + 1];

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

        if (RunTest("== RSA setup ==",            [&rsaTests](){return rsaTests.Setup();}))
        {
            RunTest("== RSA private encrypt ==",  [&rsaTests](){return rsaTests.PrivateEncrypt();});
            RunTest("== RSA private decrypt ==",  [&rsaTests](){return rsaTests.PrivateDecrypt();});
            RunTest("== RSA sign/verify ==",      [&rsaTests](){return rsaTests.SignVerify();});
            RunTest("== RSA events throttled ==", [&rsaTests](){return rsaTests.EventThrottling();});
        }
    }

    // EC_KEY APIs
    if (isEcConfigured)
{
        EcTests ecTests(logLocation);

        if (RunTest("== EC setup ==",            [&ecTests](){return ecTests.Setup();}))
        {
            RunTest("== EC sign/verify ==",      [&ecTests](){return ecTests.SignVerify();});
            RunTest("== EC events throttled ==", [&ecTests](){return ecTests.EventThrottling();});
        }
    }

    // EVP APIs (RSA and RSA PSS supported)
    if (isEvpConfigured)
    {
        EvpTests evpTests(logLocation);

        if (RunTest("== EVP setup ==",            [&evpTests](){return evpTests.Setup();}))
        {
            RunTest("== EVP sign/verify ==",      [&evpTests](){return evpTests.RSA_SignVerify();});
            RunTest("== EVP sign/verify PSS ==",  [&evpTests](){return evpTests.RSA_PSS_SignVerify();});
            RunTest("== EVP encrypt/decrypt ==",  [&evpTests](){return evpTests.RSA_EncryptDecrypt();});
            RunTest("== EVP events throttled ==", [&evpTests](){return evpTests.EventThrottling();});
        }
    }
    TestFinish();
}