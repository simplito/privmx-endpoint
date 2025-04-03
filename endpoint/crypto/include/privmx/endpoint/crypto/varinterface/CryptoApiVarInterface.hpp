/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CRYPTO_CRYPTOAPIVARINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_CRYPTO_CRYPTOAPIVARINTERFACE_HPP_

#include <Poco/Dynamic/Var.h>

#include "privmx/endpoint/core/VarDeserializer.hpp"
#include "privmx/endpoint/core/VarSerializer.hpp"
#include "privmx/endpoint/crypto/CryptoApi.hpp"
#include "privmx/endpoint/crypto/c_api.h"

namespace privmx {
namespace endpoint {
namespace crypto {

class CryptoApiVarInterface {
public:
    CryptoApiVarInterface(const core::VarSerializer& serializer)
        : _serializer(serializer) {}

    Poco::Dynamic::Var create(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var signData(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var verifySignature(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var generatePrivateKey(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var derivePrivateKey(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var derivePrivateKey2(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var derivePublicKey(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var generateKeySymmetric(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var encryptDataSymmetric(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var decryptDataSymmetric(const Poco::Dynamic::Var& args);

    Poco::Dynamic::Var convertPEMKeytoWIFKey(const Poco::Dynamic::Var& args);

    Poco::Dynamic::Var exec(privmx_CryptoApi_Method method, const Poco::Dynamic::Var& args);

private:
    static std::map<privmx_CryptoApi_Method, Poco::Dynamic::Var (CryptoApiVarInterface::*)(const Poco::Dynamic::Var&)> methodMap;

    CryptoApi _cryptoApi;
    core::VarDeserializer _deserializer;
    core::VarSerializer _serializer;
};

}  // namespace crypto
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CRYPTO_CRYPTOAPIVARINTERFACE_HPP_
