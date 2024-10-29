#ifndef _PRIVMXLIB_ENDPOINT_THREAD_MESSAGE_KEYID_FORMAT_VALIDATOR_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_MESSAGE_KEYID_FORMAT_VALIDATOR_HPP_

#include <privmx/endpoint/core/KeyIdFormatValidator.hpp>
#include <string>


namespace privmx {
namespace endpoint {
namespace thread {

class MessageKeyIdFormatValidator : public core::KeyIdFormatValidator {
public:
    void assertKeyIdFormat(const std::string& keyId) override;
    bool isKeyIdFormatValid(const std::string& keyId) override;
};

} // thread
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_MESSAGE_KEYID_FORMAT_VALIDATOR_HPP_