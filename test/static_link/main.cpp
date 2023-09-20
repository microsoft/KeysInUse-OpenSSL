#include "test.h"

#include "keysinuse_engine.h"

#include <cstring>
#include <string>
#include <memory>
#include <dlfcn.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>

using namespace std;

const char* conf_key_engine_id = "engine_id";
const char* conf_key_dynamic_path = "dynamic_path";
const char* conf_key_default_algorithms = "default_algorithms";
const char* conf_val_default_algorithms_expected = "RSA,EC";
const char* symname_bind_engine = "bind_engine";

// The KeysInUse engine should never be loaded by a statically
// linked application. A check exists in engine bind to enforce
// this. This test verified that under no circumstances will
// the engine succeed to load for a statically linked application.
int main(int argc, char **argv)
{
    string keysinuse_so_path;
    RunTest("== Setup ==", [] ()
    {
        if (!OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_DYNAMIC |
                                 OPENSSL_INIT_LOAD_CONFIG, NULL))
        {
            TestFailOpenSSLError("OPENSSL_init_crypto failed");
            TestFinish();
        }

        return true;
    });

    // Verify keysinuse engine configured but not loaded
    // by statically linked application
    RunTest("== KeysInUse Engine Load by Config ==", [&keysinuse_so_path] ()
    {
        string file(CONF_get1_default_config_file());;

        if (file.empty())
        {
            TestFail("Failed to get default config location");
            TestFinish();
        }

        CONF *conf = NCONF_new(NULL);
        if (!NCONF_load(conf, file.c_str(), NULL))
        {
            TestFailOpenSSLError("Failed to load default config");
            TestFinish();
        }

        // engine_id = keysinuse
        char* conf_value = NCONF_get_string(conf, keysinuse_conf_section, conf_key_engine_id);
        // Config value may not be present on Mariner
        if (conf_value == nullptr)
        {
            return true;
        }

        if (strcmp(engine_id, conf_value) != 0)
        {
            TestFail("Failed to get expected %s."
                    "\n\tExpected: %s"
                    "\n\tActual: %s",
                conf_key_engine_id,
                engine_id,
                conf_value);
            TestFinish();
        }

        // default_algorithms = RSA,EC
        conf_value = NCONF_get_string(conf, keysinuse_conf_section, conf_key_default_algorithms);
        // Config value may not be present on Mariner
        if (conf_value == nullptr)
        {
            return true;
        }

        if (strcmp(conf_val_default_algorithms_expected, conf_value) != 0)
        {
            TestFail("Failed to get expected %s."
                    "\n\tExpected: %s"
                    "\n\tActual: %s",
                conf_key_default_algorithms,
                conf_val_default_algorithms_expected,
                conf_value);
            TestFinish();
        }

        // dynamic_path exists.
        conf_value = NCONF_get_string(conf, keysinuse_conf_section, conf_key_dynamic_path);
        if (conf_value == nullptr)
        {
            TestFail("Failed to get %s", conf_key_dynamic_path);
            TestFinish();
        }

        keysinuse_so_path = conf_value;

        // dynamic_path points to an engine that can be loaded by OpenSSL
        shared_ptr<void> engine_so(
            dlopen(conf_value, RTLD_NOW),
            dlclose);
        if (engine_so == nullptr)
        {
            TestFail("Failed to load library at %s", conf_value);
            TestFinish();
        }

        if (dlsym(engine_so.get(), symname_bind_engine) == NULL)
        {
            TestFail("Failed to bind function %s from library: %s", symname_bind_engine, dlerror());
            TestFinish();
        }

        // Engine is configured, can be loaded by OpenSSL, and
        // is configured by default. Ensure it is not available
        // or default for this static application

        // KeysInUse engine is not accessible by ID
        shared_ptr<ENGINE> e(
            ENGINE_by_id(engine_id),
            ENGINE_free);

        if (e != nullptr)
        {
            TestFail("KeysInUse engine loaded by ID");
            TestFinish();
        }

        // KeysInUse engine is not the default for RSA
        e.reset(
            ENGINE_get_default_RSA(),
            ENGINE_free);
        if (e != nullptr &&
            strcmp(engine_id, ENGINE_get_id(e.get())) != 0)
        {
            TestFail("KeysInUse engine default for RSA");
            TestFinish();
        }

        // KeysInUse engine is not the default for EC
        e.reset(
            ENGINE_get_default_EC(),
            ENGINE_free);
        if (e != nullptr &&
            strcmp(engine_id, ENGINE_get_id(e.get())) != 0)
        {
            TestFail("KeysInUse engine default for EC");
            TestFinish();
        }

        // KeysInUse engine is not the default for EVP_PKEY_RSA
        e.reset(
            ENGINE_get_pkey_meth_engine(EVP_PKEY_RSA),
            ENGINE_free);
        if (e != nullptr &&
            strcmp(engine_id, ENGINE_get_id(e.get())) != 0)
        {
            TestFail("KeysInUse engine default for EVP_PKEY_RSA");
            TestFinish();
        }

        // KeysInUse engine is not the default for EVP_PKEY_RSA_PSS
        e.reset(
            ENGINE_get_pkey_meth_engine(EVP_PKEY_RSA_PSS),
            ENGINE_free);
        if (e != nullptr &&
            strcmp(engine_id, ENGINE_get_id(e.get())) != 0)
        {
            TestFail("KeysInUse engine default for EVP_PKEY_RSA_PSS");
            TestFinish();
        }

        return true;
    });

    // Verify keysinuse cannot be loaded through dynamic
    // engine by statically linked applicaiton.
    RunTest("== KeysInUse Engine Load by Dynamic Engine ==", [keysinuse_so_path] ()
    {
        shared_ptr<ENGINE> dynamic (
            ENGINE_by_id("dynamic"),
            ENGINE_free);

        if (!ENGINE_ctrl_cmd_string(dynamic.get(), "DIR_LOAD", "2", 0) ||
            !ENGINE_ctrl_cmd_string(dynamic.get(), "SO_PATH", keysinuse_so_path.c_str(), 0) ||
            !ENGINE_ctrl_cmd_string(dynamic.get(), "ID", "keysinuse", 0))
        {
            TestFailOpenSSLError("Failed to configure dynamic engine for keysinuse load");
            TestFinish();
        }

        if (ENGINE_ctrl_cmd_string(dynamic.get(), "LOAD", NULL, 0))
        {
            TestFail("KeysInUse engine loaded through dynamic engine");
            TestFinish();
        }
        return true;
    });

    return 0;
}