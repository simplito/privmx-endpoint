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

using namespace privmx::endpoint::core;

UserVerifier::UserVerifier(std::shared_ptr<UserVerifierInterface> userVerifier) : _userVerifier(userVerifier) {}

std::vector<bool> UserVerifier::verify(const std::vector<VerificationRequest>& request) {
    auto result = _userVerifier->verify(request);
    if(result.size() != request.size()) {
        throw MalformedVerifierResponseException("VerificationResult size is " + std::to_string(result.size()) + " with is different from VerificationRequest size" + std::to_string(request.size()));
    }
    return result;
};