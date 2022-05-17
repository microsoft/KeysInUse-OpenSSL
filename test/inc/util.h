#pragma once

bool IsNumeric(char* text);
bool IsHex(char* text);
bool CheckLog(const char* logLocation, const char* keyid, int expectedSign, int expectedDecrypt, int expectedEvents);
bool ParseLogHeader(char* header, int linenum);