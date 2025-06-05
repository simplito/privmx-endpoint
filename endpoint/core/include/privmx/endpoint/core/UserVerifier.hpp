#ifndef _PRIVMXLIB_ENDPOINT_CORE_USERVERIFIER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_USERVERIFIER_HPP_

#include <string>
#include <privmx/endpoint/core/UserVerifierInterface.hpp>
#include <privmx/utils/Debug.hpp>
namespace privmx {
namespace endpoint {
namespace core {

class UserVerifier {
public:
    UserVerifier(std::shared_ptr<UserVerifierInterface> userVerifier);
    std::vector<bool> verify(const std::vector<VerificationRequest>& request);
private:
    std::shared_ptr<UserVerifierInterface> _userVerifier;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_USERVERIFIER_HPP_
