/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_TEST_UNIT_ACCEPTALLVERIFIER_HPP_
#define _PRIVMXLIB_TEST_UNIT_ACCEPTALLVERIFIER_HPP_

#include <vector>

#include <privmx/endpoint/core/UserVerifierInterface.hpp>

namespace {

// A UserVerifier that vouches for every request.
class AcceptAllVerifier : public privmx::endpoint::core::UserVerifierInterface {
public:
    std::vector<bool> verify(const std::vector<privmx::endpoint::core::VerificationRequest>& request) override {
        return std::vector<bool>(request.size(), true);
    }
};

} // namespace

#endif // _PRIVMXLIB_TEST_UNIT_ACCEPTALLVERIFIER_HPP_
