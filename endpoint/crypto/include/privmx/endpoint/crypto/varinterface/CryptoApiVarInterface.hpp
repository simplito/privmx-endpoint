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
#include "privmx/endpoint/crypto/CryptoVarSerializer.hpp"
#include "privmx/endpoint/crypto/varinterface/ExtKeyVarInterface.hpp"
#include "privmx/endpoint/core/VarSerializer.hpp"

namespace privmx {
namespace endpoint {
namespace crypto {

class CryptoApiVarInterface {
public:
    enum METHOD {
        Create = 0,
        SignData = 1,
        GeneratePrivateKey = 2,
        DerivePrivateKey = 3,
        DerivePrivateKey2 = 4,
        DerivePublicKey = 5,
        GenerateKeySymmetric = 6,
        EncryptDataSymmetric = 7,
        DecryptDataSymmetric = 8,
        ConvertPEMKeytoWIFKey = 9,
        VerifySignature = 10,
        GenerateBip39 = 11,
        FromMnemonic = 12,
        FromEntropy = 13,
        EntropyToMnemonic = 14,
        MnemonicToEntropy = 15,
        MnemonicToSeed = 16,
        ConvertPGPKeyToBase58DERKey = 17
    };

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

    Poco::Dynamic::Var generateBip39(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var fromMnemonic(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var fromEntropy(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var entropyToMnemonic(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var mnemonicToEntropy(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var mnemonicToSeed(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var convertPGPKeyToBase58DERKey(const Poco::Dynamic::Var& args);

    Poco::Dynamic::Var exec(METHOD method, const Poco::Dynamic::Var& args);

    const core::VarSerializer::Options& getSerializerOptions() const {
        return _serializer.getOptions();
    }


private:
    static std::map<METHOD, Poco::Dynamic::Var (CryptoApiVarInterface::*)(const Poco::Dynamic::Var&)> methodMap;

    CryptoApi _cryptoApi;
    core::VarDeserializer _deserializer;
    core::VarSerializer _serializer;
};

}  // namespace crypto
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CRYPTO_CRYPTOAPIVARINTERFACE_HPP_
