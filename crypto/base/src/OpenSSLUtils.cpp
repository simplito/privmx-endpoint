/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/crypto/OpenSSLUtils.hpp>

using namespace privmx;
using namespace privmx::crypto;
using namespace std;

// Path to the CA certificates for TLS — set by endpoint::core::Config,
// read by the HTTP layer in rpc/poco.
string OpenSSLUtils::CaLocation{};
