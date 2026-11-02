#ifndef _PRIVMXLIB_ENDPOINT_CORE_USERVERIFIER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_USERVERIFIER_HPP_

#include <memory>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/core/UserVerifierInterface.hpp>
#include <string>
#include <vector>
namespace privmx {
namespace endpoint {
namespace core {

class UserVerifier {
public:
    UserVerifier(std::shared_ptr<UserVerifierInterface> userVerifier);
    std::vector<bool> verify(const std::vector<VerificationRequest>& request);
    // Every key something is about to be wrapped to, asked at now. Throws UserVerificationFailureException naming
    // each refused user and the key it was presented with.
    void assertKeysVerified(const std::string& contextId, const std::vector<UserWithPubKey>& users);

private:
    std::shared_ptr<UserVerifierInterface> _userVerifier;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_USERVERIFIER_HPP_
