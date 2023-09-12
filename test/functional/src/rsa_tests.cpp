#include "rsa_tests.h"
#include "util.h"
#include "test.h"

#include "keysinuse_engine.h"

#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

using namespace std;

void RsaTests::Cleanup()
{
    BIO_reset(rsaBio.get());
    remove(m_logLocation);
}

bool RsaTests::IsConfigured()
{
    shared_ptr<ENGINE> eng(
        ENGINE_get_default_RSA(),
        ENGINE_free);

    if (eng == nullptr)
    {
        return TestFail("Default OpenSSL implementation loaded for RSA");
    }

    const char *loaded_id = ENGINE_get_id(eng.get());
    if (strcmp(engine_id, loaded_id))
    {
        return TestFail("keysinuse engine not loaded for RSA operations, found [ %s ]", loaded_id);
    }

    return true;
}

bool RsaTests::Setup()
{
    rsaBio.reset(
        BIO_new_mem_buf((void *)rsa_keypair, -1),
        BIO_free);
    if (rsaBio == nullptr)
    {
        return TestFailOpenSSLError("Failed to create new in-mem BIO for EC key");
    }
    if (!RAND_bytes(m_plaintext, m_plaintextLen))
    {
        return TestFailOpenSSLError("Failed to generate random bytes");
    }

    return true;
}

bool RsaTests::KeyLifecycle()
{
    Cleanup();
    // Create and destroy key without using
    shared_ptr<RSA> rsaKeypair(
        PEM_read_bio_RSAPrivateKey(rsaBio.get(), nullptr, nullptr, nullptr),
        RSA_free);
    if (rsaKeypair == nullptr)
    {
        return TestFailOpenSSLError("Failed to read RSA keypair from PEM");
    }

    rsaKeypair.reset();

    // Free empty key
    RSA_free(NULL);

    return CheckLog(m_logLocation, rsa_keyid, 0, 0, 0);
}

bool RsaTests::PrivateEncrypt()
{
    Cleanup();
    shared_ptr<RSA> rsaKeypair(
        PEM_read_bio_RSAPrivateKey(rsaBio.get(), nullptr, nullptr, nullptr),
        RSA_free);
    if (rsaKeypair == nullptr)
    {
        return TestFailOpenSSLError("Failed to read RSA keypair from PEM");
    }

    int ciphertext_len = RSA_size(rsaKeypair.get());
    unsigned char ciphertext[ciphertext_len];
    unsigned char recoveredPlaintext[m_plaintextLen];

    if (RSA_private_encrypt(
            m_plaintextLen,
            m_plaintext,
            ciphertext,
            rsaKeypair.get(),
            RSA_PKCS1_PADDING) < ciphertext_len)
    {
        return TestFailOpenSSLError("Failed to encrypt data with RSA private key");
    }

    BIO_reset(rsaBio.get());
    rsaKeypair.reset(
        PEM_read_bio_RSAPrivateKey(rsaBio.get(), nullptr, nullptr, nullptr),
        RSA_free);
    if (rsaKeypair == nullptr)
    {
        return TestFailOpenSSLError("Failed to read RSA keypair from PEM");
    }

    if (RSA_public_decrypt(
            ciphertext_len,
            ciphertext,
            recoveredPlaintext,
            rsaKeypair.get(),
            RSA_PKCS1_PADDING) < m_plaintextLen)
    {
        return TestFailOpenSSLError("Failed to decrypt data with RSA private key");
    }

    if (memcmp(m_plaintext, recoveredPlaintext, m_plaintextLen) != 0)
    {
        return TestFail("Recovered m_plaintext does not match m_plaintext");
    }

    return CheckLog(m_logLocation, rsa_keyid, 1, 0, 1);
}

bool RsaTests::PrivateDecrypt()
{
    Cleanup();
    shared_ptr<RSA> rsaKeypair(
        PEM_read_bio_RSAPrivateKey(rsaBio.get(), nullptr, nullptr, nullptr),
        RSA_free);
    if (rsaKeypair == nullptr)
    {
        return TestFailOpenSSLError("Failed to read RSA keypair from PEM");
    }
    int ciphertext_len = RSA_size(rsaKeypair.get());
    unsigned char ciphertext[ciphertext_len];
    unsigned char recoveredPlaintext[m_plaintextLen];

    if (RSA_public_encrypt(
            m_plaintextLen,
            m_plaintext,
            ciphertext,
            rsaKeypair.get(),
            RSA_PKCS1_PADDING) < ciphertext_len)
    {
        return TestFailOpenSSLError("Failed to encrypt data with RSA public key");
    }

    BIO_reset(rsaBio.get());
    rsaKeypair.reset(
        PEM_read_bio_RSAPrivateKey(rsaBio.get(), nullptr, nullptr, nullptr),
        RSA_free);
    if (rsaKeypair == nullptr)
    {
        return TestFailOpenSSLError("Failed to read RSA keypair from PEM");
    }

    if (RSA_private_decrypt(
            ciphertext_len,
            ciphertext,
            recoveredPlaintext,
            rsaKeypair.get(),
            RSA_PKCS1_PADDING) < m_plaintextLen)
    {
        return TestFailOpenSSLError("Failed to decrypt data with RSA private key");
    }

    if (memcmp(m_plaintext, recoveredPlaintext, m_plaintextLen) != 0)
    {
        return TestFail("Recovered m_plaintext does not match m_plaintext");
    }
    return CheckLog(m_logLocation, rsa_keyid, 0, 1, 1);
}

bool RsaTests::SignVerify()
{
    Cleanup();
    shared_ptr<RSA> rsaKeypair(
        PEM_read_bio_RSAPrivateKey(rsaBio.get(), nullptr, nullptr, nullptr),
        RSA_free);
    if (rsaKeypair == nullptr)
    {
        return TestFailOpenSSLError("Failed to read RSA keypair from PEM");
    }
    unsigned int siglen = RSA_size(rsaKeypair.get());
    unsigned char sigbuf[siglen];

    if (!RSA_sign(
            NID_sha256,
            m_plaintext,
            m_plaintextLen,
            sigbuf,
            &siglen,
            rsaKeypair.get()))
    {
        return TestFailOpenSSLError("Failed to sign data with RSA private key");
    }

    BIO_reset(rsaBio.get());
    rsaKeypair.reset(
        PEM_read_bio_RSAPrivateKey(rsaBio.get(), nullptr, nullptr, nullptr),
        RSA_free);
    if (rsaKeypair == nullptr)
    {
        return TestFailOpenSSLError("Failed to read RSA keypair from PEM");
    }

    if (!RSA_verify(
            NID_sha256,
            m_plaintext,
            m_plaintextLen,
            sigbuf,
            siglen,
            rsaKeypair.get()))
    {
        return TestFailOpenSSLError("Failed to verify data signed with RSA private key");
    }
    return CheckLog(m_logLocation, rsa_keyid, 1, 0, 1);
}

bool RsaTests::EventThrottling()
{
    Cleanup();
    shared_ptr<RSA> rsaKeypair(
        PEM_read_bio_RSAPrivateKey(rsaBio.get(), nullptr, nullptr, nullptr),
        RSA_free);
    if (rsaKeypair == nullptr)
    {
        return TestFailOpenSSLError("Failed to read RSA keypair from PEM");
    }

    int ciphertext_len = RSA_size(rsaKeypair.get());
    unsigned char ciphertext[ciphertext_len];
    unsigned char recoveredPlaintext[m_plaintextLen];

    // Encrypt with the private key twice. Only one event should be logged,
    // but the second encrypt should be tracked
    if (RSA_private_encrypt(
            m_plaintextLen,
            m_plaintext,
            ciphertext,
            rsaKeypair.get(),
            RSA_PKCS1_PADDING) < ciphertext_len)
    {
        return TestFailOpenSSLError("Failed to encrypt data with RSA private key");
    }

    if (RSA_private_encrypt(
            m_plaintextLen,
            m_plaintext,
            ciphertext,
            rsaKeypair.get(),
            RSA_PKCS1_PADDING) < ciphertext_len)
    {
        return TestFailOpenSSLError("Failed to encrypt data a second time with RSA private key");
    }

    // Encrypt with the public key and decrypt with the private key. No event
    // should be logged, but the decrypt operation should be tracked
    if (RSA_public_encrypt(
            m_plaintextLen,
            m_plaintext,
            ciphertext,
            rsaKeypair.get(),
            RSA_PKCS1_PADDING) < ciphertext_len)
    {
        return TestFailOpenSSLError("Failed to encrypt data with RSA public key");
    }

    if (RSA_private_decrypt(
            ciphertext_len,
            ciphertext,
            recoveredPlaintext,
            rsaKeypair.get(),
            RSA_PKCS1_PADDING) < m_plaintextLen)
    {
        return TestFailOpenSSLError("Failed to decrypt data with RSA private key");
    }

    if (!CheckLog(m_logLocation, rsa_keyid, 1, 0, 1))
    {
        return false;
    }

    // Destroy the RSA key instance. Remaining uses should have
    // been tracked and logged
    rsaKeypair.reset();
    return CheckLog(m_logLocation, rsa_keyid, 2, 1, 2);
}
