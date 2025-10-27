#ifndef _PRIVMXLIB_ENDPOINT_CORE_DEFAULTUSERVERIFIERINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_DEFAULTUSERVERIFIERINTERFACE_HPP_

#include <atomic>
#include <iostream>
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
        printWarning();
        return std::vector<bool>(request.size(), true);
    };

private:
    void printWarning() {
        if (!_isWarningPrinted.exchange(true)) {
            std::cerr << "WARN: Using the default implementation of the UserVerifierInterface during connection initialization is highly discouraged, as it does not provide the protection intended by this mechanism. "
                         "For more information, see https://docs.privmx.dev." << std::endl;
        }
    }

    std::atomic_bool _isWarningPrinted = false;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_DEFAULTUSERVERIFIERINTERFACE_HPP_
