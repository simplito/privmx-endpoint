#ifndef _PRIVMXLIB_ENDPOINT_CORE_USERVERIFIERINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_USERVERIFIERINTERFACE_HPP_

#include <string>
#include <optional>

namespace privmx {
namespace endpoint {
namespace core {

/**
 * UserVerifierInterface - an interface consisting of a single verify() method, which - when implemented - should perform verification of the provided data using an external service verification
 * should be done using an external service such as an application server or a PKI server.
 */

struct VerificationRequest {
    /**
     * Id of the Context
     */
    const std::string contextId;
    /**
     * id of the sender
     */
    const std::string senderId;
    /**
     * Public key of the sender
     */
    const std::string senderPubKey;
    /**
     * The data creation date
     */
    const int64_t date;
};

class UserVerifierInterface {
public:
    /**
     * Takes as a parameter the VerificationRequest structure containing basic information of the container's element being checked.
     */
    virtual std::vector<bool> verify(const std::vector<VerificationRequest>& request) = 0;
protected:
   virtual ~UserVerifierInterface()  = default;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_USERVERIFIERINTERFACE_HPP_
