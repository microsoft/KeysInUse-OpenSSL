#include "evp_tests.h"
#include "test.h"
#include "util.h"

#include "keysinuse_engine.h"

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

using namespace std;

void EvpTests::Cleanup()
{
    BIO_reset(rsaBio.get());
    BIO_reset(rsaPssBio.get());
    remove(m_logLocation);
}

bool EvpTests::IsConfigured()
{
    // Don't return until we've checked both RSA and RSA PSS engines
    // If no engine is set, we expect the calls to pass through from
    // the default implementation
    bool correctEngine = true;
    const char *loaded_id;
    shared_ptr<ENGINE> eng(
        ENGINE_get_pkey_meth_engine(EVP_PKEY_RSA),
        ENGINE_free);
    if (eng != nullptr)
    {
        loaded_id = ENGINE_get_id(eng.get());

        if (strcmp(engine_id, loaded_id))
        {
            correctEngine = TestFail("keysinuse engine not loaded for EVP RSA operations, found [ %s ]", loaded_id);
        }
    }

    eng.reset(
        ENGINE_get_pkey_meth_engine(EVP_PKEY_RSA),
        ENGINE_free);
    if (eng != nullptr)
    {
        loaded_id = ENGINE_get_id(eng.get());

        if (strcmp(engine_id, loaded_id))
        {
            correctEngine = TestFail("keysinuse engine not loaded for EVP RSA PSS operations, found [ %s ]", loaded_id);
        }
    }

    return correctEngine;
}

bool EvpTests::Setup()
{
    if (rsaBio == nullptr)
    {
        return TestFailOpenSSLError("Failed to create new in-mem BIO for RSA key");
    }
    if (rsaPssBio == nullptr)
    {
        return TestFailOpenSSLError("Failed to create new in-mem BIO for RSA PSS key");
    }
    if (!RAND_bytes(m_plaintext, m_plaintextLen))
    {
        return TestFailOpenSSLError("Failed to generate random bytes");
    }

    return true;
}

bool EvpTests::RSA_EncryptDecrypt()
{
    Cleanup();

    shared_ptr<EVP_PKEY> evpKeyPair(
        PEM_read_bio_PrivateKey(rsaBio.get(), nullptr, nullptr, nullptr),
        EVP_PKEY_free);
    if (evpKeyPair == nullptr)
    {
        return TestFailOpenSSLError("Failed to read RSA PSS key from PEM");
    }

    shared_ptr<EVP_PKEY_CTX> evpEncryptCtx(
        EVP_PKEY_CTX_new(evpKeyPair.get(), nullptr),
        EVP_PKEY_CTX_free);
    if (!EVP_PKEY_encrypt_init(evpEncryptCtx.get()))
    {
        return TestFailOpenSSLError("Failed to initialize EVP decrypt operation");
    }

    size_t encryptedLen;
    if (!EVP_PKEY_encrypt(
            evpEncryptCtx.get(),
            nullptr,
            &encryptedLen,
            m_plaintext,
            m_plaintextLen))
    {
        return TestFailOpenSSLError("Failed to determine required buffer size for encryption");
    }

    unsigned char ciphertext[encryptedLen];
    if (!EVP_PKEY_encrypt(
            evpEncryptCtx.get(),
            ciphertext,
            &encryptedLen,
            m_plaintext,
            m_plaintextLen))
    {
        return TestFailOpenSSLError("Failed to encrypt data using RSA private key");
    }

    shared_ptr<EVP_PKEY_CTX> evpDecryptCtx(
        EVP_PKEY_CTX_new(evpKeyPair.get(), nullptr),
        EVP_PKEY_CTX_free);
    if (!EVP_PKEY_decrypt_init(evpDecryptCtx.get()))
    {
        return TestFailOpenSSLError("Failed to initialize EVP decrypt operation");
    }

    size_t decryptedLen;
    if (!EVP_PKEY_decrypt(
            evpDecryptCtx.get(),
            nullptr,
            &decryptedLen,
            ciphertext,
            encryptedLen))
    {
        return TestFailOpenSSLError("Failed to determine required buffer size for decryption");
    }

    unsigned char recoveredPlaintext[decryptedLen];
    if (!EVP_PKEY_decrypt(
            evpDecryptCtx.get(),
            recoveredPlaintext,
            &decryptedLen,
            ciphertext,
            encryptedLen))
    {
        return TestFailOpenSSLError("Failed to decrypt data using RSA public key");
    }

    if (decryptedLen != m_plaintextLen || memcmp(m_plaintext, recoveredPlaintext, m_plaintextLen) != 0)
    {
        return TestFail("Recovered m_plaintext does not match m_plaintext");
    }
    return CheckLog(m_logLocation, rsa_keyid, 0, 1, 1);
}

bool EvpTests::RSA_SignVerify()
{
    Cleanup();

    shared_ptr<EVP_PKEY> evpKeyPair(
        PEM_read_bio_PrivateKey(rsaBio.get(), nullptr, nullptr, nullptr),
        EVP_PKEY_free);
    if (evpKeyPair == nullptr)
    {
        return TestFailOpenSSLError("Failed to read RSA key from PEM");
    }

    EvpDigestSignVerify(evpKeyPair);

    return CheckLog(m_logLocation, rsa_keyid, 1, 0, 1);
}

bool EvpTests::EventThrottling()
{
    Cleanup();

    shared_ptr<EVP_PKEY> evpKeyPair(
        PEM_read_bio_PrivateKey(rsaBio.get(), nullptr, nullptr, nullptr),
        EVP_PKEY_free);
    if (evpKeyPair == nullptr)
    {
        return TestFailOpenSSLError("Failed to read RSA key from PEM");
    }

    // Sign with the private key twice. Only one event should be logged,
    // but the second encrypt should be tracked
    EvpDigestSignVerify(evpKeyPair);
    EvpDigestSignVerify(evpKeyPair);

    if (!CheckLog(m_logLocation, rsa_keyid, 1, 0, 1))
    {
        return false;
    }

    // Destroy the RSA key instance. Remaining uses should have
    // been tracked and logged. Prepare for PSS padded RSA test
    evpKeyPair.reset(
        PEM_read_bio_PrivateKey(rsaPssBio.get(), nullptr, nullptr, nullptr),
        EVP_PKEY_free);

    if (!CheckLog(m_logLocation, rsa_keyid, 2, 0, 2))
    {
        return false;
    }

    if (evpKeyPair == nullptr)
    {
        return TestFailOpenSSLError("Failed to read RSA PSS key from PEM");
    }

    // Repeat the test for PSS padded RSA
    EvpDigestSignVerify(evpKeyPair);
    EvpDigestSignVerify(evpKeyPair);

    if (!CheckLog(m_logLocation, rsa_pss_keyid, 1, 0, 1))
    {
        return false;
    }

    // Destroy the RSA PSS key instance. Remaining uses should have
    // been tracked and logged
    evpKeyPair.reset();
    return CheckLog(m_logLocation, rsa_pss_keyid, 2, 0, 2);
}

bool EvpTests::RSA_PSS_SignVerify()
{
    Cleanup();

    shared_ptr<EVP_PKEY> evpKeyPair(
        PEM_read_bio_PrivateKey(rsaPssBio.get(), nullptr, nullptr, nullptr),
        EVP_PKEY_free);
    if (evpKeyPair == nullptr)
    {
        return TestFailOpenSSLError("Failed to read RSA PSS key from PEM");
    }

    EvpDigestSignVerify(evpKeyPair);

    return CheckLog(m_logLocation, rsa_pss_keyid, 1, 0, 1);
}

bool EvpTests::EvpDigestSignVerify(shared_ptr<EVP_PKEY> evpKeyPair)
{
    shared_ptr<EVP_MD_CTX> evpSignCtx(
        EVP_MD_CTX_new(),
        EVP_MD_CTX_free);

    // Create and initialize context
    if (!EVP_DigestSignInit(
            evpSignCtx.get(),
            nullptr,
            EVP_sha256(),
            nullptr,
            evpKeyPair.get()))
    {
        return TestFailOpenSSLError("Failed to initialize EVP signing operation");
    }

    // Get buffer size
    size_t outLen;
    if (!EVP_DigestSign(
            evpSignCtx.get(),
            nullptr,
            &outLen,
            m_plaintext,
            m_plaintextLen))
    {
        return TestFailOpenSSLError("Failed to determine required buffer size for signing");
    }

    unsigned char signature[outLen];
    if (!EVP_DigestSign(
            evpSignCtx.get(),
            signature,
            &outLen,
            m_plaintext,
            m_plaintextLen))
    {
        return TestFailOpenSSLError("Failed to sign data using RSA private key");
    }

    if (!EVP_DigestVerify(
            evpSignCtx.get(),
            signature,
            outLen,
            m_plaintext,
            m_plaintextLen))
    {
        return TestFailOpenSSLError("Failed to sign data using RSA private key");
    }
    return true;
}