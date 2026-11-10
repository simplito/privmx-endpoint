#ifndef _PRIVMXLIB_TESTING_PAIRBINDINGUSERVERIFIERINTERFACE_HPP_
#define _PRIVMXLIB_TESTING_PAIRBINDINGUSERVERIFIERINTERFACE_HPP_

#include <map>
#include <string>
#include <vector>
#include <privmx/endpoint/core/UserVerifierInterface.hpp>
namespace privmx {
namespace endpoint {
namespace core {

// Accepts a request only when the key offered for a user is the one that user is known to own, the way an
// application doing its own identity check would. Every refused pair is kept for the failure message.
class PairBindingUserVerifierInterface: public virtual UserVerifierInterface {
public:
    PairBindingUserVerifierInterface(const std::map<std::string, std::string>& knownKeys) : _knownKeys(knownKeys) {}
    std::vector<bool> verify(const std::vector<VerificationRequest>& request) override {
        std::vector<bool> result;
        for (const auto& one : request) {
            auto known = _knownKeys.find(one.senderId);
            bool bound = known != _knownKeys.end() && known->second == one.senderPubKey;
            if (!bound) {
                refused.push_back(one);
            }
            result.push_back(bound);
        }
        return result;
    };
    std::vector<VerificationRequest> refused;
private:
    std::map<std::string, std::string> _knownKeys;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_TESTING_PAIRBINDINGUSERVERIFIERINTERFACE_HPP_
