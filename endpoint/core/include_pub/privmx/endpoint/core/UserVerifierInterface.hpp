#ifndef _PRIVMXLIB_ENDPOINT_CORE_USERVERIFIERINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_USERVERIFIERINTERFACE_HPP_

#include <string>
#include <optional>
#include "privmx/endpoint/core/Types.hpp"

namespace privmx {
namespace endpoint {
namespace core {

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
    /**
     * Bridge Identity 
     */
    const std::optional<BridgeIdentity> bridgeIdentity;
};

/**
 * UserVerifierInterface - an interface consisting of a single verify() method, which - when implemented - should perform verification of the provided data using an external service verification
 * should be done using an external service such as an application server or a PKI server.
 */
class UserVerifierInterface {
public:
    /**
     * Verifies whether the specified users are valid.
     * Checks if each user belonged to the Context and if this is their key in `date` and return `true` or `false` otherwise.
     * 
     * @param request List of user data to verification
     * @return List of verification results whose items correspond to the items in the input list
     */
    virtual std::vector<bool> verify(const std::vector<VerificationRequest>& request) = 0;
protected:
   virtual ~UserVerifierInterface()  = default;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_USERVERIFIERINTERFACE_HPP_
