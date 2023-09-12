#include "ec_tests.h"
#include "test.h"
#include "util.h"

#include "keysinuse_engine.h"

#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

using namespace std;

void EcTests::Cleanup()
{
    BIO_reset(ecBio.get());
    remove(m_logLocation);
}

bool EcTests::IsConfigured()
{
    shared_ptr<ENGINE> eng(
        ENGINE_get_default_EC(),
        ENGINE_free);

    if (eng == nullptr)
    {
        return TestFail("Default OpenSSL implementation loaded for EC");
    }

    const char *loaded_id = ENGINE_get_id(eng.get());
    if (strcmp(engine_id, loaded_id))
    {
        return TestFail("keysinuse engine not loaded for EC operations, found [ %s ]", loaded_id);
    }

    return true;
}

bool EcTests::Setup()
{
    ecBio.reset(
        BIO_new_mem_buf((void *)ec_keypair, -1),
        BIO_free);
    if (ecBio == nullptr)
    {
        return TestFailOpenSSLError("Failed to create new in-mem BIO for EC key");
    }
    if (!RAND_bytes(m_plaintext, m_plaintextLen))
    {
        return TestFailOpenSSLError("Failed to generate random bytes");
    }

    return true;
}

bool EcTests::KeyLifecycle()
{
    Cleanup();
    shared_ptr<EC_KEY> ecKeyPair(
        PEM_read_bio_ECPrivateKey(ecBio.get(), nullptr, nullptr, nullptr),
        EC_KEY_free);

    if (ecKeyPair == nullptr)
    {
        return TestFailOpenSSLError("Failed to read EC key from PEM");
    }

    ecKeyPair.reset();

    // Free empty key
    EC_KEY_free(NULL);

    return CheckLog(m_logLocation, ec_keyid, 0, 0, 0);
}

bool EcTests::SignVerify()
{
    Cleanup();
    shared_ptr<EC_KEY> ecKeyPair(
        PEM_read_bio_ECPrivateKey(ecBio.get(), nullptr, nullptr, nullptr),
        EC_KEY_free);

    if (ecKeyPair == nullptr)
    {
        return TestFailOpenSSLError("Failed to read EC key from PEM");
    }

    unsigned int siglen = ECDSA_size(ecKeyPair.get());
    unsigned char signature[siglen];
    unsigned char recoveredPlaintext[m_plaintextLen];

    if (!ECDSA_sign(
            0,
            m_plaintext,
            m_plaintextLen,
            signature,
            &siglen,
            ecKeyPair.get()))
    {
        return TestFailOpenSSLError("Failed to sign data with EC private key");
    }

    BIO_reset(ecBio.get());
    ecKeyPair.reset(
        PEM_read_bio_ECPrivateKey(ecBio.get(), nullptr, nullptr, nullptr),
        EC_KEY_free);
    if (ecKeyPair == nullptr)
    {
        return TestFailOpenSSLError("Failed to read EC key from PEM");
    }

    if (!ECDSA_verify(
            0,
            m_plaintext,
            m_plaintextLen,
            signature,
            siglen,
            ecKeyPair.get()))
    {
        return TestFailOpenSSLError("Failed to verify signed data with EC public key");
    }
    return CheckLog(m_logLocation, ec_keyid, 1, 0, 1);
}

bool EcTests::EventThrottling()
{
    Cleanup();
    shared_ptr<EC_KEY> ecKeyPair(
        PEM_read_bio_ECPrivateKey(ecBio.get(), nullptr, nullptr, nullptr),
        EC_KEY_free);

    if (ecKeyPair == nullptr)
    {
        return TestFailOpenSSLError("Failed to read EC key from PEM");
    }

    unsigned int siglen = ECDSA_size(ecKeyPair.get());
    unsigned char signature[siglen];
    unsigned char recoveredPlaintext[m_plaintextLen];

    // Sign with the private key twice. Only one event should be logged,
    // but the second encrypt should be tracked
    if (!ECDSA_sign(
            0,
            m_plaintext,
            m_plaintextLen,
            signature,
            &siglen,
            ecKeyPair.get()))
    {
        return TestFailOpenSSLError("Failed to sign data with EC private key");
    }

    if (!ECDSA_sign(
            0,
            m_plaintext,
            m_plaintextLen,
            signature,
            &siglen,
            ecKeyPair.get()))
    {
        return TestFailOpenSSLError("Failed to sign data a second time with EC private key");
    }

    if (!CheckLog(m_logLocation, ec_keyid, 1, 0, 1))
    {
        return false;
    }

    // Destroy the EC key instance. Remaining uses should have
    // been tracked and logged
    ecKeyPair.reset();
    return CheckLog(m_logLocation, ec_keyid, 2, 0, 2);
}