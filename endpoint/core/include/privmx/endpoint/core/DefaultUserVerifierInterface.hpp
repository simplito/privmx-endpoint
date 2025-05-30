#ifndef _PRIVMXLIB_ENDPOINT_CORE_DEFAULTUSERVERIFIERINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_DEFAULTUSERVERIFIERINTERFACE_HPP_

#include <string>
#include <optional>
#include <privmx/endpoint/core/UserVerifierInterface.hpp>
#include <privmx/utils/Debug.hpp>
namespace privmx {
namespace endpoint {
namespace core {

class DefaultUserVerifierInterface: public virtual UserVerifierInterface {
public:
    std::vector<bool> verify(const std::vector<VerificationRequest>& request) override {
        PRIVMX_DEBUG("UserVerifierInterface", "VerificationRequest", "Default")
        return std::vector<bool>(request.size(), true);
    };
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_DEFAULTUSERVERIFIERINTERFACE_HPP_
