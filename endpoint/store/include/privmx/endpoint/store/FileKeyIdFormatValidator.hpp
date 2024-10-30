#ifndef _PRIVMXLIB_ENDPOINT_STORE_FILE_KEYID_FORMAT_VALIDATOR_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_FILE_KEYID_FORMAT_VALIDATOR_HPP_

#include <privmx/endpoint/core/KeyIdFormatValidator.hpp>
#include <string>


namespace privmx {
namespace endpoint {
namespace store {

class FileKeyIdFormatValidator : public core::KeyIdFormatValidator {
public:
    void assertKeyIdFormat(const std::string& keyId) override;
    bool isKeyIdFormatValid(const std::string& keyId) override;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_FILE_KEYID_FORMAT_VALIDATOR_HPP_