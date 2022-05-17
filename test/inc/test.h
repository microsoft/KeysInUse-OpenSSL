#pragma once

#include <functional>

void RunTest(const char* stage, std::function<bool()> testFunc);
void TestPass();
bool TestFail(const char* reason, ...);
bool TestFailOpenSSLError(const char* reason);
void TestFinish();