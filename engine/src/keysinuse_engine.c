#include "keysinuse_engine.h"
#include "logging.h"

#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include "keysinuse_rsa.h"
#include "keysinuse_rsa_evp.h"
#endif // OPENSSL_NO_RSA

#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#include "keysinuse_ec.h"
#endif // OPENSSL_NO_EC

#include <openssl/conf.h>

int init(ENGINE *e)
{
    log_debug("Engine init");
    return 1;
}

int finish(ENGINE *e)
{
    log_debug("Engine finish");
    return 1;
}

int destroy(ENGINE *e)
{
    // Reset default engine
#ifndef OPENSSL_NO_RSA
    RSA_METHOD *keysinuse_rsa_method = (RSA_METHOD *)ENGINE_get_RSA(e);

    if (keysinuse_rsa_method)
    {
        RSA_meth_free(keysinuse_rsa_method);
        ENGINE_set_RSA(e, NULL);
    }
    keysinuse_destroy_pkey_methods();
#endif // OPENSSL_NO_RSA
#ifndef OPENSSL_NO_EC
    EC_KEY_METHOD *keysinuse_ec_key_method = (EC_KEY_METHOD *)ENGINE_get_EC(e);

    if (keysinuse_ec_key_method)
    {
        EC_KEY_METHOD_free(keysinuse_ec_key_method);
        ENGINE_set_EC(e, NULL);
    }
#endif // OPENSSL_NO_EC

    log_debug("Engine destroy");

    return 1;
}

static int control(ENGINE *e, int cmd, long i, void *p, void (*func)(void))
{
    log_debug("Engine control (%d)", cmd);

    int ret = 0;
    switch (cmd)
    {
    case ENGINE_CTRL_LOGGING_BACKOFF:
        set_logging_backoff(i);
        ret = 1;
        break;
    case ENGINE_CTRL_LOGGING_ID:
        set_logging_id((char *)p);
        ret = 1;
        break;
    default:
        log_error("Unsupported command code: %d", cmd);
    }

    return ret;
}

static void config_init()
{
    // This will read the engine's config explicitly, so that the
    // engine's config is still used when the engine is loaded
    // programatically, and not included in the default config
    // (e.g. on CBL-Mariner). This is also done early, so that
    // the engine does not bind any functions anything if logging
    // is disabled.
    CONF *conf = NCONF_new(NULL);
    if (!NCONF_load(conf, keysinuse_conf_location, NULL))
    {
        log_error("Failed to load keysinuse config,OPENSSL_%ld", ERR_get_error());
        goto err;
    }

    int success = 0;
    long num_val = 0;
    char *string_val = NULL;
    for (int i = 0; i < (sizeof(supported_cmds) / sizeof(ENGINE_CMD_DEFN)) && supported_cmds[i].cmd_num != 0; i++)
    {
        if (supported_cmds[i].cmd_flags & ENGINE_CMD_FLAG_STRING)
        {
            string_val = NCONF_get_string(conf, keysinuse_conf_section, supported_cmds[i].cmd_name);
            success = string_val != NULL;
        }
        else if (supported_cmds[i].cmd_flags & ENGINE_CMD_FLAG_NUMERIC)
        {
            success = NCONF_get_number(conf, keysinuse_conf_section, supported_cmds[i].cmd_name, &num_val);
        }

        if (success)
        {
            control(
                NULL,
                supported_cmds[i].cmd_num,
                num_val,
                string_val,
                NULL);
        }
        else
        {
            unsigned long error = ERR_get_error();
            if (ERR_GET_REASON(error) != CONF_R_NO_VALUE)
            {
                log_error("Failed to get config value for control %s,OPENSSL_%ld", supported_cmds[i].cmd_name, error);
            }
        }
    }

err:
    NCONF_free(conf);
}

OPENSSL_EXPORT
int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns)
{
    if (!CRYPTO_THREAD_run_once(&log_once, log_init))
    {
        log_error("Error in one-time logging initialization,OPENSSL_%ld", ERR_get_error());
        return 0;
    }

    // Return value of ENGINE_get_static_state should match in the
    // dynamically loaded case. The Keys-In-Use engine will not work
    // with statically linked applications, since it must transparently
    // pass through and make upcalls to libcrypto.
    if (ENGINE_get_static_state() != fns->static_state)
    {
        log_error("Statically linked application,PID_%d", getpid());
        return 0;
    }

    if (!CRYPTO_THREAD_run_once(&config_once, config_init))
    {
        log_error("Error in one-time config initialization,OPENSSL_%ld", ERR_get_error());
        return 0;
    }

    if (!ENGINE_set_id(e, engine_id) ||
        !ENGINE_set_name(e, engine_name) ||
        !ENGINE_set_init_function(e, init) ||
        !ENGINE_set_finish_function(e, finish) ||
        !ENGINE_set_destroy_function(e, destroy) ||
        !ENGINE_set_ctrl_function(e, control) ||
        !ENGINE_set_cmd_defns(e, supported_cmds))
    {
        log_error("Error in engine bind,OPENSSL_%ld", ERR_get_error());
        return 0;
    }

    // No point in binding functions for passthrough if
    // logging is disabled
    if (global_logging_disabled())
    {
        return 1;
    }

#ifndef OPENSSL_NO_RSA
    RSA_METHOD *keysinuse_rsa_method = NULL;
    int rsa_success = get_RSA_meth(&keysinuse_rsa_method);
    log_debug("Bind RSA: %s", rsa_success ? "SUCCEEDED" : "FAILED");
    if (!rsa_success)
    {
        return 0;
    }
    RSA_meth_set1_name(keysinuse_rsa_method, "keysinuse RSA method");

    if (!ENGINE_set_RSA(e, keysinuse_rsa_method))
    {
        log_error("Error in binding keysinuse RSA method,OPENSSL_%ld", ERR_get_error());
        return 0;
    }
    if (!ENGINE_set_default_RSA(e))
    {
        log_error("Failed to set keysinuse RSA method as default,OPENSSL_%ld", ERR_get_error());
    }

    if (ENGINE_get_pkey_meth_engine(EVP_PKEY_RSA) ||
        ENGINE_get_pkey_meth_engine(EVP_PKEY_RSA_PSS))
    {
        if (!init_keysinuse_pkey_methods() ||
            !ENGINE_set_pkey_meths(e, keysinuse_pkey_methods))
        {
            log_error("Error in binding keysinuse PKEY methods,OPENSSL_%ld", ERR_get_error());
            return 0;
        }
        if (!ENGINE_set_default_pkey_meths(e))
        {
            log_error("Failed to set keysinuse PKEY methods as default,OPENSSL_%ld", ERR_get_error());
        }
    }
#endif // OPENSSL_NO_RSA

#ifndef OPENSSL_NO_EC
    EC_KEY_METHOD *keysinuse_ec_key_method = NULL;
    int ec_success = get_EC_meth(&keysinuse_ec_key_method);
    log_debug("Bind EC: %s", ec_success ? "SUCCEEDED" : "FAILED");
    if (!ec_success)
    {
        return 0;
    }

    if (!ENGINE_set_EC(e, keysinuse_ec_key_method))
    {
        log_error("Error in binding keysinuse EC method,OPENSSL_%ld", ERR_get_error());
        return 0;
    }

    if (!ENGINE_set_default_EC(e))
    {
        log_error("Failed to set keysinuse EC_KEY method as default,OPENSSL_%ld", ERR_get_error());
    }
#endif // OPENSSL_NO_EC

    log_debug("Engine bound");

    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()