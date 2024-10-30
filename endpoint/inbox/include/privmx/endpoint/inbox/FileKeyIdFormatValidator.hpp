#ifndef _PRIVMXLIB_ENDPOINT_INBOX_FILE_KEYID_FORMAT_VALIDATOR_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_FILE_KEYID_FORMAT_VALIDATOR_HPP_

#include <privmx/endpoint/core/KeyIdFormatValidator.hpp>
#include <string>


namespace privmx {
namespace endpoint {
namespace inbox {

class FileKeyIdFormatValidator : public core::KeyIdFormatValidator {
public:
    void assertKeyIdFormat(const std::string& keyId) override;
    bool isKeyIdFormatValid(const std::string& keyId) override;
};

} // inbox
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_INBOX_FILE_KEYID_FORMAT_VALIDATOR_HPP_