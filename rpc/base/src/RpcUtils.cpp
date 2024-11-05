/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/rpc/RpcUtils.hpp>

using namespace privmx::rpc;

const std::regex RpcUtils::HOSTNAME_REGEX{"^(([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9-_]*[a-zA-Z0-9_]).)*([A-Za-z0-9_]|[A-Za-z0-9_][A-Za-z0-9-_]*[A-Za-z0-9_])$"};

bool RpcUtils::isValidHostname(const std::string& hostname) {
    return std::regex_match(hostname, HOSTNAME_REGEX);
}
