/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/crypto/ecc/ECDHE.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>
#include <privmx/utils/Utils.hpp>

using namespace privmx;
using namespace privmx::crypto;
using namespace privmx::utils;
using namespace std;

ECDHE::ECDHE(const PrivateKey& private_key, const PublicKey& public_key) {
    string secret = private_key.derive(public_key);
    _secret = Utils::fillTo32(secret);
}
