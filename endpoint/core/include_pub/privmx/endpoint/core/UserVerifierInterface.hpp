#ifndef _PRIVMXLIB_ENDPOINT_CORE_USERVERIFIERINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_USERVERIFIERINTERFACE_HPP_

#include <string>
#include <optional>

namespace privmx {
namespace endpoint {
namespace core {

/**
 * 'UserVerificationInterface' ....
 */

struct VerificationRequest {
    const std::string contextId;
    const std::string senderId;
    const std::string senderPubKey;
    const int64_t date;
};

class UserVerifierInterface {
public:
    virtual std::vector<bool> verify(const std::vector<VerificationRequest>& request) = 0;
protected:
   virtual ~UserVerifierInterface()  = default;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_USERVERIFIERINTERFACE_HPP_
