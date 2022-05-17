#pragma once

class functional_test
{
protected:
    static const unsigned int m_plaintextLen = 32;
    unsigned char m_plaintext[m_plaintextLen];
    const char *m_logLocation;

public:
    functional_test(const char *logLocation) : m_logLocation(logLocation) {}
};