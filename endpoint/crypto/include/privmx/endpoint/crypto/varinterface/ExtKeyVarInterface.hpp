/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CRYPTO_EXTKEYVARINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_CRYPTO_EXTKEYVARINTERFACE_HPP_

#include <Poco/Dynamic/Var.h>

#include "privmx/endpoint/core/VarDeserializer.hpp"
#include "privmx/endpoint/core/VarSerializer.hpp"
#include "privmx/endpoint/crypto/ExtKeyVarSerializer.hpp"

namespace privmx {
namespace endpoint {
namespace crypto {

class ExtKeyVarInterface {
public:
    enum METHOD {
        FromSeed = 0,
        FromBase58 = 1,
        GenerateRandom = 2,
        Derive = 3,
        DeriveHardened = 4,
        GetPrivatePartAsBase58 = 5,
        GetPublicPartAsBase58 = 6,
        GetPrivateKey = 7,
        GetPublicKey = 8,
        GetPrivateEncKey = 9,
        GetPublicKeyAsBase58Address = 10,
        GetChainCode = 11,
        VerifyCompactSignatureWithHash = 12,
        IsPrivate = 13
    };

    ExtKeyVarInterface(const crypto::ExtKey& extKey, const core::VarSerializer& serializer)
        : _extKey(std::move(extKey)), _serializer(serializer) {}

    Poco::Dynamic::Var fromSeed(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var fromBase58(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var generateRandom(const Poco::Dynamic::Var& args);


    Poco::Dynamic::Var derive(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var deriveHardened(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getPrivatePartAsBase58(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getPublicPartAsBase58(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getPrivateKey(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getPublicKey(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getPrivateEncKey(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getPublicKeyAsBase58Address(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getChainCode(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var verifyCompactSignatureWithHash(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var isPrivate(const Poco::Dynamic::Var& args);

    Poco::Dynamic::Var exec(METHOD method, const Poco::Dynamic::Var& args);

private:
    static std::map<METHOD, Poco::Dynamic::Var (ExtKeyVarInterface::*)(const Poco::Dynamic::Var&)> methodMap;

    crypto::ExtKey _extKey;
    core::VarDeserializer _deserializer;
    core::VarSerializer _serializer;
};

}  // namespace crypto
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CRYPTO_EXTKEYVARINTERFACE_HPP_
