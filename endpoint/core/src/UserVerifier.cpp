/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/UserVerifier.hpp"
#include "privmx/endpoint/core/CoreException.hpp"
#include <privmx/utils/Utils.hpp>

using namespace privmx::endpoint::core;

UserVerifier::UserVerifier(std::shared_ptr<UserVerifierInterface> userVerifier) : _userVerifier(userVerifier) {}

std::vector<bool> UserVerifier::verify(const std::vector<VerificationRequest>& request) {
    std::vector<bool> result;
    try {
        result = _userVerifier->verify(request);
    } catch (...) { throw core::UserVerificationMethodUnhandledException(); }
    if (result.size() != request.size()) {
        throw MalformedVerifierResponseException(
            "VerificationResult size is " +
            std::to_string(result.size()) +
            " which is different from VerificationRequest size" +
            std::to_string(request.size())
        );
    }
    return result;
};

void UserVerifier::assertKeysVerified(const std::string& contextId, const std::vector<UserWithPubKey>& users) {
    if (users.empty()) {
        return;
    }
    std::vector<VerificationRequest> requests;
    const int64_t now = privmx::utils::Utils::getNowTimestamp();
    for (const auto& user : users) {
        requests.push_back(
            {.contextId = contextId,
             .senderId = user.userId,
             .senderPubKey = user.pubKey,
             .date = now,
             .bridgeIdentity = std::nullopt}
        );
    }
    const auto verified = verify(requests);
    std::string refused;
    for (size_t i = 0; i < users.size(); ++i) {
        if (!verified[i]) {
            refused += (refused.empty() ? "" : ",") + users[i].userId + ":" + users[i].pubKey;
        }
    }
    if (!refused.empty()) {
        throw UserVerificationFailureException("refused=" + refused);
    }
}
