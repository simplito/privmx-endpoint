/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/crypto/varinterface/CryptoApiVarInterface.hpp"

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/varinterface/VarInterfaceUtil.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::crypto;

std::map<CryptoApiVarInterface::METHOD, Poco::Dynamic::Var (CryptoApiVarInterface::*)(const Poco::Dynamic::Var&)>
    CryptoApiVarInterface::methodMap = {{Create, &CryptoApiVarInterface::create},
                                        {SignData, &CryptoApiVarInterface::signData},
                                        {GeneratePrivateKey, &CryptoApiVarInterface::generatePrivateKey},
                                        {DerivePrivateKey, &CryptoApiVarInterface::derivePrivateKey},
                                        {DerivePrivateKey2, &CryptoApiVarInterface::derivePrivateKey2},
                                        {DerivePublicKey, &CryptoApiVarInterface::derivePublicKey},
                                        {GenerateKeySymmetric, &CryptoApiVarInterface::generateKeySymmetric},
                                        {EncryptDataSymmetric, &CryptoApiVarInterface::encryptDataSymmetric},
                                        {DecryptDataSymmetric, &CryptoApiVarInterface::decryptDataSymmetric},
                                        {ConvertPEMKeytoWIFKey, &CryptoApiVarInterface::convertPEMKeytoWIFKey},
                                        {VerifySignature, &CryptoApiVarInterface::verifySignature},

                                        {GenerateBip39, &CryptoApiVarInterface::generateBip39},
                                        {FromMnemonic, &CryptoApiVarInterface::fromMnemonic},
                                        {FromEntropy, &CryptoApiVarInterface::fromEntropy},
                                        {EntropyToMnemonic, &CryptoApiVarInterface::entropyToMnemonic},
                                        {MnemonicToEntropy, &CryptoApiVarInterface::mnemonicToEntropy},
                                        {MnemonicToSeed, &CryptoApiVarInterface::mnemonicToSeed},
                                        {ConvertPGPAsn1KeyToBase58DERKey, &CryptoApiVarInterface::convertPGPAsn1KeyToBase58DERKey}};


Poco::Dynamic::Var CryptoApiVarInterface::create(const Poco::Dynamic::Var& args) {
    core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    _cryptoApi = CryptoApi::create();
    return {};
}

Poco::Dynamic::Var CryptoApiVarInterface::signData(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto data = _deserializer.deserialize<core::Buffer>(argsArr->get(0), "data");
    auto key = _deserializer.deserialize<std::string>(argsArr->get(1), "privateKey");
    auto result = _cryptoApi.signData(data, key);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var CryptoApiVarInterface::verifySignature(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto data = _deserializer.deserialize<core::Buffer>(argsArr->get(0), "data");
    auto signature = _deserializer.deserialize<core::Buffer>(argsArr->get(1), "signature");
    auto key = _deserializer.deserialize<std::string>(argsArr->get(2), "privateKey");
    auto result = _cryptoApi.verifySignature(data, signature, key);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var CryptoApiVarInterface::generatePrivateKey(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto basestring = _deserializer.deserializeOptional<std::string>(argsArr->get(0), "randomSeed");
    auto result = _cryptoApi.generatePrivateKey(basestring);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var CryptoApiVarInterface::derivePrivateKey(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto password = _deserializer.deserialize<std::string>(argsArr->get(0), "password");
    auto salt = _deserializer.deserialize<std::string>(argsArr->get(1), "salt");
    auto result = _cryptoApi.derivePrivateKey(password, salt);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var CryptoApiVarInterface::derivePrivateKey2(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto password = _deserializer.deserialize<std::string>(argsArr->get(0), "password");
    auto salt = _deserializer.deserialize<std::string>(argsArr->get(1), "salt");
    auto result = _cryptoApi.derivePrivateKey2(password, salt);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var CryptoApiVarInterface::derivePublicKey(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto privkey = _deserializer.deserialize<std::string>(argsArr->get(0), "privateKey");
    auto result = _cryptoApi.derivePublicKey(privkey);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var CryptoApiVarInterface::generateKeySymmetric(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    auto result = _cryptoApi.generateKeySymmetric();
    return _serializer.serialize(result);
}

Poco::Dynamic::Var CryptoApiVarInterface::encryptDataSymmetric(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto data = _deserializer.deserialize<core::Buffer>(argsArr->get(0), "data");
    auto key = _deserializer.deserialize<core::Buffer>(argsArr->get(1), "symmetricKey");
    auto result = _cryptoApi.encryptDataSymmetric(data, key);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var CryptoApiVarInterface::decryptDataSymmetric(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto data = _deserializer.deserialize<core::Buffer>(argsArr->get(0), "data");
    auto key = _deserializer.deserialize<core::Buffer>(argsArr->get(1), "symmetricKey");
    auto result = _cryptoApi.decryptDataSymmetric(data, key);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var CryptoApiVarInterface::convertPEMKeytoWIFKey(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto keyPEM = _deserializer.deserialize<std::string>(argsArr->get(0), "pemKey");
    auto result = _cryptoApi.convertPEMKeytoWIFKey(keyPEM);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var CryptoApiVarInterface::generateBip39(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto strength = _deserializer.deserialize<int64_t>(argsArr->get(0), "strength");
    auto password = _deserializer.deserialize<std::string>(argsArr->get(1), "password");
    auto result = _cryptoApi.generateBip39(strength, password);
    auto serialized = _serializer.serialize(result);

    auto extKeyVar = new ExtKeyVarInterface(result.ext_key, getSerializerOptions());
    Poco::JSON::Object::Ptr obj = serialized.extract<Poco::JSON::Object::Ptr>();
    obj->set("extKey", (int64_t)extKeyVar);
    return obj;
}

Poco::Dynamic::Var CryptoApiVarInterface::fromMnemonic(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto mnemonic = _deserializer.deserialize<std::string>(argsArr->get(0), "mnemonic");
    auto password = _deserializer.deserialize<std::string>(argsArr->get(1), "password");
    auto result = _cryptoApi.fromMnemonic(mnemonic, password);
    auto serialized = _serializer.serialize(result);

    auto extKeyVar = new ExtKeyVarInterface(result.ext_key, getSerializerOptions());
    Poco::JSON::Object::Ptr obj = serialized.extract<Poco::JSON::Object::Ptr>();
    obj->set("extKey", (int64_t)extKeyVar);
    return obj;
}

Poco::Dynamic::Var CryptoApiVarInterface::fromEntropy(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto entropy = _deserializer.deserialize<core::Buffer>(argsArr->get(0), "entropy");
    auto password = _deserializer.deserialize<std::string>(argsArr->get(1), "password");
    auto result = _cryptoApi.fromEntropy(entropy, password);
    auto serialized = _serializer.serialize(result);

    auto extKeyVar = new ExtKeyVarInterface(result.ext_key, getSerializerOptions());
    Poco::JSON::Object::Ptr obj = serialized.extract<Poco::JSON::Object::Ptr>();
    obj->set("extKey", (int64_t)extKeyVar);
    return obj;
}

Poco::Dynamic::Var CryptoApiVarInterface::entropyToMnemonic(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto entropy = _deserializer.deserialize<core::Buffer>(argsArr->get(0), "entropy");
    auto result = _cryptoApi.entropyToMnemonic(entropy);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var CryptoApiVarInterface::mnemonicToEntropy(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto mnemonic = _deserializer.deserialize<std::string>(argsArr->get(0), "mnemonic");
    auto result = _cryptoApi.mnemonicToEntropy(mnemonic);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var CryptoApiVarInterface::mnemonicToSeed(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto mnemonic = _deserializer.deserialize<std::string>(argsArr->get(0), "mnemonic");
    auto password = _deserializer.deserialize<std::string>(argsArr->get(1), "password");
    auto result = _cryptoApi.mnemonicToSeed(mnemonic, password);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var CryptoApiVarInterface::convertPGPAsn1KeyToBase58DERKey(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto keyPEM = _deserializer.deserialize<std::string>(argsArr->get(0), "pgpKey");
    auto result = _cryptoApi.convertPGPAsn1KeyToBase58DERKey(keyPEM);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var CryptoApiVarInterface::exec(METHOD method, const Poco::Dynamic::Var& args) {
    auto it = methodMap.find(method);
    if (it == methodMap.end()) {
        throw core::InvalidMethodException();
    }
    return (*this.*(it->second))(args);
}
