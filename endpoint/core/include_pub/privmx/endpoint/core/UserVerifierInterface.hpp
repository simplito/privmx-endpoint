#ifndef _PRIVMXLIB_ENDPOINT_CORE_USERVERIFIERINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_USERVERIFIERINTERFACE_HPP_

#include "privmx/endpoint/core/Types.hpp"
#include <optional>
#include <string>

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
     * Bridge Identity.
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
     * Group key-tree statements that would advance a group's verified state (not the first contact of this device
     * with the group, per GroupApi) are checked twice: at the date they were signed and at the current time. A signer chooses the date it signs, so a key its owner has rotated away from or
     * revoked is shut out only by the current-time answer: the implementation must answer `false` for a request whose
     * `date` is now as soon as the key stops being the user's, and should not serve that answer from a long-lived
     * cache. The library itself reuses a current-time answer for at most a minute.
     *
     * The callback may run on library background threads.
     *
     * @param request List of user data to verification
     * @return List of verification results whose items correspond to the items in the input list
     */
    virtual std::vector<bool> verify(const std::vector<VerificationRequest>& request) = 0;

protected:
    virtual ~UserVerifierInterface() = default;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_USERVERIFIERINTERFACE_HPP_
