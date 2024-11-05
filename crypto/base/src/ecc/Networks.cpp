/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/crypto/ecc/Networks.hpp>

using namespace privmx;
using namespace privmx::crypto;

const Networks::Network Networks::BITCOIN{{0x0488B21E, 0x0488ADE4}, 0x00, 0x80};
