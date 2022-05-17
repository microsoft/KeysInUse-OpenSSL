#include "test.h"

#include <iostream>

#include <openssl/err.h>

const int failMsgMax = 256;
static int exitCode = 0;

void RunTest(const char* stage, std::function<bool()> testFunc)
{
    std::cout << stage << std::endl;
    if (testFunc())
    {
        TestPass();
    }
}

void TestPass()
{
    std::cout << "\033[1;32m"<< "PASS" << "\033[0m" << std::endl;
}

bool TestFail(const char* reason, ...)
{
    va_list args;
    char msgBuf[failMsgMax];

    va_start(args, reason);

    vsnprintf(msgBuf, failMsgMax, reason, args);

    std::cout << "\033[1;31m"<< "FAIL: " << msgBuf << "\033[0m" << std::endl;
    exitCode = 1;

    va_end(args);
    return false;
}

bool TestFailOpenSSLError(const char* reason)
{
    int errorCode = ERR_get_error();
    if (errorCode > 0)
    {
        return TestFail("%s: %s", reason, ERR_reason_error_string(errorCode));
    }
    else
    {
        return TestFail("%s", reason);
    }
}

void TestFinish()
{
    exit(exitCode);
}