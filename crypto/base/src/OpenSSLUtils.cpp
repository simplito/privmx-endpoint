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

// Sciezka do certyfikatow CA dla TLS - ustawiana przez endpoint::core::Config,
// czytana przez warstwe HTTP w rpc/poco.
string OpenSSLUtils::CaLocation{};
