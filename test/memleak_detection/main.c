#include <openssl/crypto.h>
#include <openssl/pem.h>

int mem_leaks_cb(const char *str, size_t len, void *u)
{
    printf("%s\n", str);
}

void test_reload_cert(const char *pem_path, int iterations)
{
    int mcount_pre, fcount_pre,
        mcount_post, fcount_post,
        mcount_net, fcount_net;
    FILE *fp;
    X509 *cert;

    if ((fp = fopen(pem_path, "r")) == NULL)
    {
        printf("Failed to open %s\n", pem_path);
        return;
    }

    printf("Reading and closing %s %d times...\n", pem_path, iterations);

    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    CRYPTO_get_alloc_counts(&mcount_pre, NULL, &fcount_pre);

    for (int i = 0; i < iterations; i++)
    {
        cert = PEM_read_X509(fp, NULL, NULL, NULL);
        X509_free(cert);
        rewind(fp);
    }

    CRYPTO_get_alloc_counts(&mcount_post, NULL, &fcount_post);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_OFF);

    mcount_net = mcount_post - mcount_pre;
    fcount_net = fcount_post - fcount_pre;

    printf("\tTotal allocations: %d\n", mcount_net);
    printf("\tTotal frees: %d\n", fcount_net);
    printf("\tAllocations - free: %d\n", mcount_net - fcount_net);
}

int main(int argc, char *argv[])
{
    CRYPTO_set_mem_debug(1);

    if (!OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_DYNAMIC | OPENSSL_INIT_LOAD_CONFIG, NULL))
    {
        return 0;
    }

    for (int i = 1; i < argc-1; i+=2)
    {
        test_reload_cert(argv[i], atoi(argv[i+1]) );
    }

    if (CRYPTO_mem_leaks_cb(mem_leaks_cb, NULL) == 1)
    {
        printf("No leaks found!\n");
    }

    OPENSSL_cleanup();

    return 1;
}