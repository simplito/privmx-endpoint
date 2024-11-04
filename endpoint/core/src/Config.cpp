/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/Config.hpp"

#include <privmx/crypto/OpenSSLUtils.hpp>

using namespace privmx::endpoint::core;

void Config::setCertsPath(const std::string& certsPath) {
    crypto::OpenSSLUtils::CaLocation = certsPath;
}
