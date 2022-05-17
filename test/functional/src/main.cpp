#include "test.h"
#include "ec_tests.h"
#include "evp_tests.h"
#include "rsa_tests.h"

#include <keysinuse_engine.h>
#include "logging.h"

using namespace std;

const char* logging_id = "functionaltest";

int main(int argc, char **argv)
{
    char logLocation[LOG_PATH_LEN+1];

    // Call OPENSSL_init_crypto to force config file load
    RunTest("== Setup ==", [&] ()
    {
        if (!OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL))
        {
            TestFailOpenSSLError("OPENSSL_init_crypto failed");
            TestFinish();
        }

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
    {
        bool isConfigured;
        RsaTests rsaTests(logLocation);
        RunTest("== RSA Configuration ==", [&rsaTests, &isConfigured](){return (isConfigured = rsaTests.IsConfigured());});

        if (isConfigured)
        {
            RunTest("== RSA private encrypt ==",  [&rsaTests](){return rsaTests.PrivateEncrypt();});
            RunTest("== RSA private decrypt ==",  [&rsaTests](){return rsaTests.PrivateDecrypt();});
            RunTest("== RSA sign/verify ==",      [&rsaTests](){return rsaTests.SignVerify();});
            RunTest("== RSA events throttled ==", [&rsaTests](){return rsaTests.EventThrottling();});
        }
    }

    // EC_KEY APIs
    {
        bool isConfigured;
        EcTests ecTests(logLocation);
        RunTest("== EC Configuration ==", [&ecTests, &isConfigured](){return (isConfigured = ecTests.IsConfigured());});

        if (isConfigured)
        {
            RunTest("== EC sign/verify ==",      [&ecTests](){return ecTests.SignVerify();});
            RunTest("== EC events throttled ==", [&ecTests](){return ecTests.EventThrottling();});
        }
    }

    // EVP APIs (RSA and RSA PSS supported)
    {
        bool isConfigured;
        EvpTests evpTests(logLocation);
        RunTest("== EVP Configuration ==", [&evpTests, &isConfigured](){return (isConfigured = evpTests.IsConfigured());});

        // Only run the tests if EVP is configured as expected
        if (isConfigured)
        {
            RunTest("== EVP sign/verify ==",      [&evpTests](){return evpTests.RSA_SignVerify();});
            RunTest("== EVP sign/verify PSS ==",  [&evpTests](){return evpTests.RSA_PSS_SignVerify();});
            RunTest("== EVP encrypt/decrypt ==",  [&evpTests](){return evpTests.RSA_EncryptDecrypt();});
            RunTest("== EVP events throttled ==", [&evpTests](){return evpTests.EventThrottling();});
        }
    }
    TestFinish();
}