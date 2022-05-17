// filesystem header is a c++17 feature and may be
// under experimental/filesystem on older compilers
#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif

#include <cstring>
#include <fstream>
#include <iostream>
#include <unistd.h>
#include <syslog.h>
#include <sys/stat.h>

#include "keys.h"
#include "test.h"

extern "C" {
#include "common.h"
#include "logging.h"
}

using namespace std;

time_t globalTestStart;
const time_t testLoggingBackoff = 1;
const char* test_logging_id = "unittest";

static char log_path[LOG_PATH_LEN+1];

bool TestLogging(int level);

int main(int argc, char **argv)
{
    globalTestStart = time(nullptr);
    log_init();
    set_logging_id(const_cast<char*>(test_logging_id));
    cout << "\033[1;34m"<< "common.h" << "\033[0m" << endl;

    RunTest("== global_logging_disabled ==", [] () {
        // Logging should be enabled by default
        if (global_logging_disabled())
        {
            return TestFail("Logging disabled by default");
        }

        // Negative backoff should always disable logging
        set_logging_backoff(-1);
        if (!global_logging_disabled())
        {
            return TestFail("Logging not disabled after changing backoff to negative value");
        }
        return true;
    });

    keysinuse_info* info = new_keysinuse_info();
    RunTest("== new_keysinuse_info ==", [&] () {
        char empty_identifier[KEY_IDENTIFIER_CHAR_SIZE] = {0};

        if (info == nullptr)
        {
            return TestFail("keysinuse_info not allocated");
        }

        if (info->disabled != 0 ||
            info->first_use != 0 ||
            info->last_logged_use != 0 ||
            info->encrypts != 0 ||
            info->decrypts != 0 ||
            memcmp(info->key_identifier, empty_identifier, KEY_IDENTIFIER_CHAR_SIZE) != 0)
        {
            return TestFail("keysinuse_info not zeroed");
        }
        return true;
    });

    RunTest("== should_log ==", [&] () {
        // Current epoch time is used to validate timestamps in the test
        struct timespec testStart;
        if (clock_gettime(CLOCK_MONOTONIC, &testStart) < 0)
        {
            return TestFail("Failed to get current clock time to perform unit test. (errno %lds)", errno);
        }

        // Logging backoff should still be negative from previous test
        if (should_log(info))
        {
            return TestFail("should_log returned true when logging backoff was negative");
        }

        // should_log will update info->last_logged_use when true. should_log should return true here since it hasn't succeeded yet
        set_logging_backoff(testLoggingBackoff);
        if (!should_log(info))
        {
            return TestFail("should_log returned false when logging backoff was %lds and no info->last_logged_use was not set", testLoggingBackoff);
        }

        if (info->last_logged_use - testStart.tv_sec < 0)
        {
            return TestFail("info->last_logged_use set to %lds, but test started at %lds", info->last_logged_use, testStart.tv_sec);
        }

        testStart.tv_sec = info->last_logged_use;

        // Ensure throttling works
        if (should_log(info))
        {
            return TestFail("should_log returned true when logging backoff was %lds and a logging event occured", testLoggingBackoff);
        }

        sleep(testLoggingBackoff);

        // Logging backoff should have expired
        if (!should_log(info))
        {
            return TestFail("should_log returned false when logging backoff was %lds and backoff time expired", testLoggingBackoff);
        }

        // Verify last_logged_use timestamps fit the logging backoff
        if (info->last_logged_use - testStart.tv_sec < testLoggingBackoff)
        {
            return TestFail("info->last_logged_use set to %d, but previous logging event was at %d", info->last_logged_use, testStart.tv_sec);
        }

        // If logging backoff is 0, subsequent calls to should_log should always succeed
        set_logging_backoff(0);
        if (!should_log(info) || !should_log(info))
        {
            return TestFail("should_log did not always return true when logging backoff was 0s");
        }
        return true;
    });

    RunTest("== generate_key_id ==", [&] () {
        // Hash RSA key from pre-calculated DER encoding of public key
        unsigned char rsaKeyBuf[sizeof(rsaPubKey)];
        memcpy(rsaKeyBuf, rsaPubKey, sizeof(rsaPubKey));

        if (!generate_key_id(rsaKeyBuf, sizeof(rsaPubKey), info->key_identifier))
        {
            return TestFail("generate_key_id failed");
        }

        if (strcmp(info->key_identifier, rsa_keyid) != 0)
        {
            return TestFail("Incorrect key identifier for RSA key.\n  Expected:\t%s\n  Actual:\t%s",
                rsa_keyid, info->key_identifier);
        }

        // Hash EC key from pre-calculated octet encoding of public key
        unsigned char ecKeyBuf[sizeof(ecPubKey)];
        memcpy(ecKeyBuf, ecPubKey, sizeof(ecPubKey));

        if (!generate_key_id(ecKeyBuf, sizeof(ecPubKey), info->key_identifier))
        {
            return TestFail("generate_key_id failed");
        }

        if (strcmp(info->key_identifier, ec_keyid) != 0)
        {
            return TestFail("Incorrect key identifier for EC key.\n  Expected:\t%s\n  Actual:\t%s",
                ec_keyid, info->key_identifier);
        }
        return true;
    });

    cout << endl;
    cout << "\033[1;34m"<< "logging.h" << "\033[0m" << endl;

    // If we fail to derive the logging path, it means
    // something is bad with the format string.
    uid_t euid = geteuid();

    RunTest("== log_notice ==", [&euid] () {
        if (sprintf(log_path, LOG_PATH_TMPL, "not", euid, test_logging_id) == 0)
        {
            TestFail("Failed to derive logging path: %d", errno);
            TestFinish();
        }
        remove(log_path);

        return TestLogging(LOG_NOTICE);
    });

    RunTest("== log_error ==", [&euid] () {
        if (sprintf(log_path, LOG_PATH_TMPL, "err", euid, test_logging_id) == 0)
        {
            TestFail("Failed to derive error logging path: %d", errno);
            TestFinish();
        }
        remove(log_path);

        return TestLogging(LOG_ERR);
    });
    TestFinish();
}

// Helper function. Logs a simple test message, then a message
// with a format string and arguments. Parses the log file and
// verifies events are logged in expected format.
bool TestLogging(int level)
{
    bool foundMsg = false;
    bool foundMsgWithArgs = false;
    string levelStr;
    string logPath;
    const char* msg = "Test notice";
    const char* stringParam = "param_1";
    int intParam = rand();
    long longParam = lrand48();

    switch(level)
    {
    case LOG_NOTICE:
        levelStr = "not";
        logPath = log_path;
        log_notice(msg);
        log_notice("%s,%d,%ld", msg, intParam, longParam);
        break;
    case LOG_ERR:
        levelStr = "err";
        logPath = log_path;
        log_error(msg);
        log_error("%s,%d,%ld", msg, intParam, longParam);
        break;
    default:
        return TestFail("Untested logging level %d", level);
    }

    // Change permissions only long enough to open a stream to parse
    if (chmod(logPath.c_str(), 0400) == -1)
    {
        return TestFail("Failed to enable reading of log file %d", errno);
    }

    ifstream logFile(logPath);

    if (chmod(logPath.c_str(), 0200) == -1)
    {
        return TestFail("Failed to enable reading of log file %d", errno);
    }

    char *token;
    string line;
    while(getline(logFile, line))
    {
        token = strtok((char*)line.c_str(), ",");
        time_t logTime = atol(token);

        token = strtok(nullptr, ",");
        fs::path loggedPath = fs::path(token);

        if (loggedPath == fs::read_symlink("/proc/self/exe"))
        {
            // Verify header
            if (logTime < globalTestStart)
            {
                return TestFail("Found event logged with a process start time earlier than expected\n  Expected after %ld\n  Actual: %ld",
                    globalTestStart, logTime);
            }

            token = strtok(nullptr, "!");
            if (strcmp(token, levelStr.c_str()) != 0)
            {
                return TestFail("Expected event to be logged with level \"%s\", found %s", levelStr, token);
            }

            // Verify message body
            token = strtok(nullptr, ",");
            if (strcmp(token, msg) != 0)
            {
                return TestFail("Expected message body to begin with %s, found %s", msg, token);
            }

            // Verify arguments, should be second message for this process
            if (foundMsg)
            {
                token = strtok(nullptr, ",");
                if (atoi(token) != intParam)
                {
                    return TestFail("Expected integer %d at in second argument, found %s", intParam, token);
                }

                token = strtok(nullptr, ",");
                if (atol(token) != longParam)
                {
                    return TestFail("Expected long integer %ld in first argument, found %s", longParam, token);
                }

                foundMsgWithArgs = true;
            }
            else
            {
                foundMsg = true;
            }

            token = strtok(nullptr, "");
            if (token != nullptr)
            {
                return TestFail("Expected no more data in event, found %s", token);
            }
        }
    }

    if (!foundMsg || !foundMsgWithArgs)
    {
        return TestFail("Not all messages logged");
    }

    return true;
}