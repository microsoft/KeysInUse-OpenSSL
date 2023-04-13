#ifndef KEYSINUSE_ENGINE_H
#define KEYSINUSE_ENGINE_H

#include <openssl/engine.h>

#define ENGINE_CTRL_LOGGING_ID ENGINE_CMD_BASE + 1
#define ENGINE_CTRL_LOGGING_BACKOFF ENGINE_CMD_BASE + 2

// Constants
static const char *engine_id = "keysinuse";
static const char *engine_name = "An engine for logging public key identifiers";
static const char *keysinuse_conf_location = "/etc/keysinuse/keysinuse.cnf";
static const char *keysinuse_conf_section = "keysinuse_section";
static CRYPTO_ONCE log_once = CRYPTO_ONCE_STATIC_INIT;
static CRYPTO_ONCE config_once = CRYPTO_ONCE_STATIC_INIT;

static const ENGINE_CMD_DEFN supported_cmds[] =
{
    // logging_id = <unique ID (string)>
    {
        ENGINE_CTRL_LOGGING_ID,
        "logging_id",
        "Unique ID added to log filenames. On systems with multiple tenants writing to a shared filesystem, this should be unique per tenant.",
        ENGINE_CMD_FLAG_STRING
    },
    // logging_backoff = <number of seconds>
    {
        ENGINE_CTRL_LOGGING_BACKOFF,
        "logging_backoff",
        "Minimum number of seconds the engine will wait before logging key usage events again. Negative value to disable logging.",
        ENGINE_CMD_FLAG_NUMERIC
    },
    // Control commands null terminator
    {0, NULL, NULL, 0}
};

#endif // KEYSINUSE_ENGINE_H
