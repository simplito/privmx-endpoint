/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CRYPTO_CRYPTOVARSERIALIZER_HPP_
#define _PRIVMXLIB_ENDPOINT_CRYPTO_CRYPTOVARSERIALIZER_HPP_

#include <Poco/Dynamic/Var.h>

#include <privmx/endpoint/core/VarSerializer.hpp>
#include <string>

#include "privmx/endpoint/crypto/Types.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template<>
Poco::Dynamic::Var VarSerializer::serialize<crypto::BIP39_t>(const crypto::BIP39_t& val);

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CRYPTO_CRYPTOVARSERIALIZER_HPP_
