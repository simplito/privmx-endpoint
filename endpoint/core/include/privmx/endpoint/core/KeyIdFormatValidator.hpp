#ifndef _PRIVMXLIB_ENDPOINT_CORE_KEYID_FORMAT_VALIDATOR_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_KEYID_FORMAT_VALIDATOR_HPP_

#include <string>

namespace privmx {
namespace endpoint {
namespace core {

class KeyIdFormatValidator {
public:
    virtual void assertKeyIdFormat(const std::string& keyId) = 0;
    virtual bool isKeyIdFormatValid(const std::string& keyId) = 0;
protected:
    // Default Key
    // - 16 bites of data in Hex
    bool hasDefaultKeyIdFormat(const std::string& keyId);

    // Extended KeyId
    // - always in < > brackets
    // - separator between elements '-'
    // - if prefix is empty separator is not used for prefix
    bool hasExtendedKeyIdFormat(const std::string& keyId, const std::string& prefix, size_t dataElements);
};

} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_KEYID_FORMAT_VALIDATOR_HPP_