#ifndef _PRIVMXLIB_TESTING_FALSEUSERVERIFIERINTERFACE_HPP_
#define _PRIVMXLIB_TESTING_FALSEUSERVERIFIERINTERFACE_HPP_

#include <vector>
#include <privmx/endpoint/core/UserVerifierInterface.hpp>
namespace privmx {
namespace endpoint {
namespace core {

class FalseUserVerifierInterface: public virtual UserVerifierInterface {
public:
    std::vector<bool> verify(const std::vector<VerificationRequest>& request) override {
        return std::vector<bool>(request.size(), false);
    };
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_TESTING_FALSEUSERVERIFIERINTERFACE_HPP_
