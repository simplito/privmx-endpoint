#ifndef _PRIVMXLIB_TESTING_FALSEUSERVERIFIERINTERFACE_HPP_
#define _PRIVMXLIB_TESTING_FALSEUSERVERIFIERINTERFACE_HPP_

#include <functional>
#include <set>
#include <string>
#include <vector>
#include <gtest/gtest.h>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/Exception.hpp>
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

// The application's verifier knowing that these keys are not their users' keys (a key the Bridge substituted, as
// far as the client can tell), and vouching for every other one.
class RefusingKeyVerifier: public virtual UserVerifierInterface {
public:
    explicit RefusingKeyVerifier(std::set<std::string> refused) : _refused(std::move(refused)) {}
    std::vector<bool> verify(const std::vector<VerificationRequest>& request) override {
        std::vector<bool> result;
        for (const auto& r : request) {
            result.push_back(_refused.count(r.senderPubKey) == 0);
        }
        return result;
    };
private:
    std::set<std::string> _refused;
};

// `call` throws UserVerificationFailureException, i.e. the verifier refused before anything was sent.
inline void expectVerificationFailure(const std::function<void()>& call) {
    try {
        call();
        ADD_FAILURE() << "expected UserVerificationFailureException, nothing was thrown";
    } catch (const Exception& e) {
        EXPECT_EQ(e.getCode(), UserVerificationFailureException().getCode()) << e.getFull();
    }
}

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_TESTING_FALSEUSERVERIFIERINTERFACE_HPP_
