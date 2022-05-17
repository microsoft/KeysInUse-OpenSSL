# Troubleshooting

## Common Problems

### __I've installed the keysinuse engine, but nothing is being written to `var/log/keysinuse`__
1. Make sure your application is actually signing/decrypting with your certificate's _private_ key. Public key usage is not logged.
2. Make sure your application has been reloaded or restarted since the keysinuse package was installed. The OpenSSL config must at least be re-read.
3. Make sure the keysinuse engine is installed by running `openssl engine`. If not, refer to [Config Files](#Config-Files).
4. Make sure your application loads the OpenSSL config. If your application links to `libssl` in addition to `libcrypto`, then this should happen by default. Some OpenSSL calls trigger a config load, but you may need to add `OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG)` to your applcation's startup.
5. Make sure your application is not calling directly into a different OpenSSL engine or the default OpenSSL implementation
   - i.e. using an API such as `ENGINE_get_RSA` or `RSA_get_default_method` to get a handle to a different crypto implementation
6. Check whether `logging_backoff` is set in `keysinuse.cnf`
   - If it isn't present, the default is one hour
   - If it is present and less than 0, logging is disabled

### __I'm seeing error events related to permissions__
The keysinuse engine and scanner verify the permissions on logging files in directories to prevent tampering. The logging directory permissions should be `1733`, and the log files should be `0200`. The log files are separated by the UID of the applicaiton as well. Check that the owner and group of a file match the UID embedded in the file name (`keysinuse_<logging_level>_<uid>_<logging_id>.log`). Also check the user of the application writing the events, and the file it's attempting to write to.

## Config files
The keysinuse engine is enabled via the global OpenSSL config. During install, a separate config file is created at `/usr/lib/keysinuse/keysinuse.cnf` and is included in the global config using the `.include` directive. The contents of the file should look something like this:
```dosini
[ openssl_init ]
engines = engine_section

[ engine_section ]
keysinuse = keysinuse_section

[ keysinuse_section ]
engine_id = keysinuse
dynamic_path = /usr/lib/x86_64-linux-gnu/engines-1.1/keysinuse.so
default_algorithms = RSA,EC
init = 0
logging_id = 09ff86267faabd42884b553a1589bcd6
```

If the engine won't load at all, or OpenSSL continues crashing on config load, ensure:
1. The keysinuse config file is properly formatted
2. The keysinuse config file is included by the global OpenSSL config
3. The engine shared object is correctly placed at `dynamic_path`

## Disabling the engine
1. Uninstall the package  
    - Debian: `dpkg -r keysinuse`
    - RPM: `rpm -e keysinuse`
2. Use the keysinuse util to disable the engine without uninstalling  
    - `/usr/lib/keysinuse/keysinuseutil -update-default uninstall`
3. Disable the engine from the config manually  
    a) Open the OpenSSL config  
    b) Comment out/delete the line including the keysinuse config file
      - e.g. `.include /usr/lib/keysinuse/keysinuse.cnf`

Remember to reload/restart any services that were using the engine for the changes to take effect