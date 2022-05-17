#include <vector>
#include <chrono>
#include <string.h>
#include <pthread.h>
#include <sys/times.h>
#include <sys/resource.h>

#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/err.h>

const unsigned int rsa_key_len = 2048;
const unsigned int plaintext_len = 32;
const unsigned int num_threads = 1;
unsigned int iterations = 1;

using namespace std;
using namespace chrono;

typedef struct
{
    double u_first;
    double s_first;
    double u_avg;
    double s_avg;
} thread_result;

void *thread_routine(void *key);

int main(int argc, char **argv)
{
    char err_buf[256];
    double u_first = 0.0;
    double s_first = 0.0;
    double u_avg = 0.0;
    double s_avg = 0.0;
    double u_avg_reload = 0.0;
    double s_avg_reload = 0.0;
    struct rusage r_start, r_end;

    if (argc > 1)
    {
        iterations = atoi(argv[1]);
    }

    printf("Initializing crypto\n");
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

    ENGINE *eng = ENGINE_get_default_RSA();
    if (eng == nullptr)
    {
        printf("Default OpenSSL implementation loaded\n");
    }
    else
    {
        printf("Using engine %s\n", ENGINE_get_id(eng));
    }

    printf("Generating RSA key\n");
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);

    RSA *keypair = RSA_new();
    RSA_generate_key_ex(keypair, rsa_key_len, e, NULL);

    printf("Generating random %d-bit message\n", plaintext_len * 8);
    int ciphertext_len = RSA_size(keypair);
    unsigned char plaintext[plaintext_len];
    unsigned char ciphertext[ciphertext_len];
    unsigned char recovered_plaintext[plaintext_len];

    if (!RAND_bytes(plaintext, plaintext_len))
    {
        printf("Failed to generate %d random bytes: %ld\n", plaintext_len, ERR_get_error());
        return 0;
    }

    printf("Running first encryption with expected overhead\n");
    getrusage(RUSAGE_SELF, &r_start);
    RSA_private_encrypt(
        plaintext_len,
        plaintext,
        ciphertext,
        keypair,
        RSA_PKCS1_PADDING);
    getrusage(RUSAGE_SELF, &r_end);

    printf("Verifying message can be decrypted\n");
    if (RSA_public_decrypt(
            ciphertext_len,
            ciphertext,
            recovered_plaintext,
            keypair,
            RSA_PKCS1_PADDING) != plaintext_len)
    {
        printf("Decrypted text unexpected length\n");
        return 0;
    }

    if (memcmp(plaintext, recovered_plaintext, plaintext_len) != 0)
    {
        printf("Recovered plaintext does not match plaintext\n");
        return 0;
    }

    u_first = (r_end.ru_utime.tv_sec - r_start.ru_utime.tv_sec) * 1000.0 + (r_end.ru_utime.tv_usec - r_start.ru_utime.tv_usec) / 1000.0;
    s_first = (r_end.ru_stime.tv_sec - r_start.ru_stime.tv_sec) * 1000.0 + (r_end.ru_stime.tv_usec - r_start.ru_stime.tv_usec) / 1000.0;

    printf("Encrypting message %d times\n", iterations);
    getrusage(RUSAGE_SELF, &r_start);
    for (int i = 0; i < iterations; i++)
        RSA_private_encrypt(
            plaintext_len,
            plaintext,
            ciphertext,
            keypair,
            RSA_PKCS1_PADDING);
    getrusage(RUSAGE_SELF, &r_end);

    u_avg = (r_end.ru_utime.tv_sec - r_start.ru_utime.tv_sec) * 1000.0 + (r_end.ru_utime.tv_usec - r_start.ru_utime.tv_usec) / 1000.0;
    s_avg = (r_end.ru_stime.tv_sec - r_start.ru_stime.tv_sec) * 1000.0 + (r_end.ru_stime.tv_usec - r_start.ru_stime.tv_usec) / 1000.0;
    u_avg /= iterations;
    s_avg /= iterations;

    printf("Reloading key and encrypting message %d times\n", iterations);
    int length;
    char *bytes;
    RSA *reloaded_keypair;
    double u_elapsed, s_elapsed;

    BIO *rsa_write_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(rsa_write_bio, keypair, nullptr, nullptr, 0, nullptr, nullptr);

    length = (int)BIO_get_mem_data(rsa_write_bio, &bytes);
    BIO *rsa_read_bio = BIO_new_mem_buf(bytes, length);

    for (int i = 0; i < iterations; i++)
    {
        rsa_read_bio = BIO_new_mem_buf(bytes, length);

        RSA *reloaded_keypair = RSA_new();
        PEM_read_bio_RSAPrivateKey(rsa_read_bio, &reloaded_keypair, nullptr, nullptr);

        getrusage(RUSAGE_SELF, &r_start);
        RSA_private_encrypt(
            plaintext_len,
            plaintext,
            ciphertext,
            reloaded_keypair,
            RSA_PKCS1_PADDING);

        getrusage(RUSAGE_SELF, &r_end);

        u_elapsed = (r_end.ru_utime.tv_sec - r_start.ru_utime.tv_sec) * 1000.0 + (r_end.ru_utime.tv_usec - r_start.ru_utime.tv_usec) / 1000.0;
        s_elapsed = (r_end.ru_stime.tv_sec - r_start.ru_stime.tv_sec) * 1000.0 + (r_end.ru_stime.tv_usec - r_start.ru_stime.tv_usec) / 1000.0;

        u_avg_reload += u_elapsed / iterations;
        s_avg_reload += s_elapsed / iterations;

        RSA_free(reloaded_keypair);
    }

    // Single thread results
    printf("\nFirst encryption time:\n");
    printf("\tUsr: %fms\n", u_first);
    printf("\tSys: %fms\n", s_first);
    printf("\tTot: %fms\n", u_first + s_first);
    printf("Average encryption time (no reload):\n");
    printf("\tUsr: %fms\n", u_avg);
    printf("\tSys: %fms\n", s_avg);
    printf("\tTot: %fms\n", u_avg + s_avg);
    printf("Average encryption time (reloaded key):\n");
    printf("\tUsr: %fms\n", u_avg_reload);
    printf("\tSys: %fms\n", s_avg_reload);
    printf("\tTot: %fms\n", u_avg_reload + s_avg_reload);

    u_first = 0.0;
    s_first = 0.0;
    u_avg = 0.0;
    s_avg = 0.0;

    printf("\nMultithreaded test (%d threads)\n", num_threads);
    pthread_t tids[num_threads];
    for (int i = 0; i < num_threads; i++)
    {
        pthread_create(&tids[i], NULL, &thread_routine, keypair);
        printf("Thread %ld started\n", tids[i]);
    }

    printf("\n");

    for (int i = 0; i < num_threads; i++)
    {
        void *res;
        pthread_join(tids[i], &res);
        thread_result *elapsed_times = (thread_result *)res;

        printf("Thread %ld finished\n", tids[i]);
        printf("\tFirst encryption time:\n");
        printf("\t\tUsr: %fms\n", elapsed_times->u_first);
        printf("\t\tSys: %fms\n", elapsed_times->s_first);
        printf("\t\tTot: %fms\n", elapsed_times->u_first + elapsed_times->s_first);
        printf("\tAverage encryption time:\n");
        printf("\t\tUsr: %fms\n", elapsed_times->u_avg);
        printf("\t\tSys: %fms\n", elapsed_times->s_avg);
        printf("\t\tTot: %fms\n", elapsed_times->u_avg + elapsed_times->s_avg);

        u_first += elapsed_times->u_first;
        s_first += elapsed_times->s_first;
        u_avg += elapsed_times->u_avg;
        s_avg += elapsed_times->s_avg;

        free(elapsed_times);
    }

    u_first /= num_threads;
    s_first /= num_threads;
    u_avg /= num_threads;
    s_avg /= num_threads;

    printf("Thread Averages\n");
    printf("\tFirst encryption time:\n");
    printf("\t\tUsr: %fms\n", u_first);
    printf("\t\tSys: %fms\n", s_first);
    printf("\t\tTot: %fms\n", u_first + s_first);
    printf("\tAverage encryption time:\n");
    printf("\t\tUsr: %fms\n", u_avg);
    printf("\t\tSys: %fms\n", s_avg);
    printf("\t\tTot: %fms\n", u_avg + s_avg);

    RSA_free(keypair);
    ENGINE_free(eng);
    BIO_free(rsa_write_bio);
    BIO_free(rsa_read_bio);
    return 1;
}

void *thread_routine(void *key)
{
    RSA *keypair = (RSA *)key;
    thread_result *elapsed_times = new thread_result;
    struct rusage r_start, r_end;

    int ciphertext_len = RSA_size(keypair);
    unsigned char plaintext[plaintext_len];
    unsigned char ciphertext[ciphertext_len];
    unsigned char recovered_plaintext[plaintext_len];

    if (!RAND_bytes(plaintext, plaintext_len))
    {
        printf("Failed to generate %d random bytes: %ld\n", plaintext_len, ERR_get_error());
        pthread_exit(nullptr);
    }

    getrusage(RUSAGE_SELF, &r_start);
    RSA_private_encrypt(
        plaintext_len,
        plaintext,
        ciphertext,
        keypair,
        RSA_PKCS1_PADDING);
    getrusage(RUSAGE_SELF, &r_end);

    if (RSA_public_decrypt(
            ciphertext_len,
            ciphertext,
            recovered_plaintext,
            keypair,
            RSA_PKCS1_PADDING) != plaintext_len)
    {
        printf("Decrypted text unexpected length\n");
        pthread_exit(nullptr);
    }

    if (memcmp(plaintext, recovered_plaintext, plaintext_len) != 0)
    {
        printf("Recovered plaintext does not match plaintext\n");
        pthread_exit(nullptr);
    }

    elapsed_times->u_first = (r_end.ru_utime.tv_sec - r_start.ru_utime.tv_sec) * 1000.0 + (r_end.ru_utime.tv_usec - r_start.ru_utime.tv_usec) / 1000.0;
    elapsed_times->s_first = (r_end.ru_stime.tv_sec - r_start.ru_stime.tv_sec) * 1000.0 + (r_end.ru_stime.tv_usec - r_start.ru_stime.tv_usec) / 1000.0;

    getrusage(RUSAGE_SELF, &r_start);
    for (int i = 0; i < iterations; i++)
        RSA_private_encrypt(
            plaintext_len,
            plaintext,
            ciphertext,
            keypair,
            RSA_PKCS1_PADDING);
    getrusage(RUSAGE_SELF, &r_end);

    elapsed_times->u_avg = (r_end.ru_utime.tv_sec - r_start.ru_utime.tv_sec) * 1000.0 + (r_end.ru_utime.tv_usec - r_start.ru_utime.tv_usec) / 1000.0;
    elapsed_times->s_avg = (r_end.ru_stime.tv_sec - r_start.ru_stime.tv_sec) * 1000.0 + (r_end.ru_stime.tv_usec - r_start.ru_stime.tv_usec) / 1000.0;
    elapsed_times->u_avg /= iterations;
    elapsed_times->s_avg /= iterations;

    pthread_exit(elapsed_times);
}