// filesystem header is a c++17 feature and may be
// under experimental/filesystem on older compilers
#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif

#include "util.h"
#include "test.h"

#include <ctype.h>
#include <sys/stat.h>

#include <fstream>
#include <iostream>
#include <string>
#include <cstring>

using namespace std;

bool IsNumeric(char *text)
{
    while (*text != '\0')
    {
        if (!isdigit(*text))
        {
            return false;
        }
        text++;
    }
    return true;
}

bool IsHex(char *text)
{
    while (*text != '\0')
    {
        if (!isxdigit(*text))
        {
            return false;
        }
        text++;
    }
    return true;
}

bool CheckLog(const char *logLocation, const char *keyid, int expectedSign, int expectedDecrypt, int expectedEvents)
{
    // Change permissions only long enough to open a stream to parse
    if (chmod(logLocation, 0400) == -1)
    {
        return TestFail("Failed to enable reading of log file %d", errno);
    }

    ifstream logFile(logLocation);

    if (chmod(logLocation, 0200) == -1)
    {
        return TestFail("Failed to reset permissions on log file %d", errno);
    }

    string line;
    int linenum = 1;

    int keyUsedSign = 0;
    int keyUsedDecrypt = 0;
    int eventCount = 0;

    while (getline(logFile, line))
    {
        char *header = strtok((char *)line.c_str(), "!");
        char *body = strtok(nullptr, "");
        // Expect header in format <epoch time>,<proc path>,<level>
        if (!ParseLogHeader(header, linenum))
        {
            continue;
        }

        // Expect key usage message in format <key_id>,<sign_count>,<decrypt_count>,<first_use>,<last_use>
        char *token = strtok(body, ",");
        if (token == nullptr)
        {
            return TestFail("Malformed message on line %d", linenum);
        }
        if (IsHex(token) &&
            strcmp(token, keyid) == 0)
        {
            // sign count
            int count = 0;
            token = strtok(nullptr, ",");
            if (token == nullptr || !IsNumeric(token))
            {
                return TestFail("Invalid sign count on line %d", linenum);
            }
            keyUsedSign += atoi(token);

            // decrypt count
            token = strtok(nullptr, ",");
            if (token == nullptr || !IsNumeric(token))
            {
                return TestFail("Invalid decrypt count on line %d", linenum);
            }
            keyUsedDecrypt += atoi(token);

            // timestamps
            token = strtok(nullptr, ",");
            if (token == nullptr || !IsNumeric(token))
            {
                return TestFail("Invalid FirstUse time on line %d", linenum);
            }
            long firstUse = atol(token);

            token = strtok(nullptr, ",");
            if (!IsNumeric(token))
            {
                return TestFail("Invalid LastUse time on line %d", linenum);
            }
            long lastUse = atol(token);

            if (firstUse > lastUse)
            {
                return TestFail("FirstUse timestamp later than LastUse timestamp on line %d", linenum);
            }

            eventCount++;
        }
        linenum++;
    }

    if (keyUsedSign != expectedSign)
    {
        return TestFail("Found %d sign operations, expected %d", keyUsedSign, expectedSign);
    }

    if (keyUsedDecrypt != expectedDecrypt)
    {
        return TestFail("Found %d decrypt operations, exected %d", keyUsedDecrypt, expectedDecrypt);
    }

    if (eventCount != expectedEvents)
    {
        return TestFail("Found %d distinct key use events, expected %d", eventCount, expectedEvents);
    }
    return true;
}

bool ParseLogHeader(char *header, int linenum)
{
    if (header == nullptr)
    {
        return TestFail("Header not found on line %d", linenum);
    }

    char *token = strtok(header, ",");
    if (token == nullptr || !IsNumeric(token))
    {
        return TestFail("Invalid rocess start time on line %d", linenum);
    }

    token = strtok(nullptr, ",");
    if (token == nullptr)
    {
        return TestFail("Invalid process path on line %d", linenum);
    }

    fs::path loggedPath = fs::path(token);
    if (loggedPath == fs::read_symlink("/proc/self/exe"))
    {
        token = strtok(nullptr, ",");
        if (token == nullptr || strcmp(token, "not") != 0)
        {
            return TestFail("Logged event for this process with a different level than notice on line %d", linenum);
        }
        return true;
    }

    return false;
}