/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/crypto/varinterface/ExtKeyVarInterface.hpp"

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/varinterface/VarInterfaceUtil.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::crypto;

std::map<ExtKeyVarInterface::METHOD, Poco::Dynamic::Var (ExtKeyVarInterface::*)(const Poco::Dynamic::Var&)>
    ExtKeyVarInterface::methodMap = {
                                        {FromSeed, &ExtKeyVarInterface::fromSeed},
                                        {FromBase58, &ExtKeyVarInterface::fromBase58},
                                        {GenerateRandom, &ExtKeyVarInterface::generateRandom},

                                        {Derive, &ExtKeyVarInterface::derive},
                                        {DeriveHardened, &ExtKeyVarInterface::deriveHardened},
                                        {GetPrivatePartAsBase58, &ExtKeyVarInterface::getPrivatePartAsBase58},
                                        {GetPublicPartAsBase58, &ExtKeyVarInterface::getPublicPartAsBase58},
                                        {GetPrivateKey, &ExtKeyVarInterface::getPrivateKey},
                                        {GetPublicKey, &ExtKeyVarInterface::getPublicKey},
                                        {GetPrivateEncKey, &ExtKeyVarInterface::getPrivateEncKey},
                                        {GetPublicKeyAsBase58Address, &ExtKeyVarInterface::getPublicKeyAsBase58Address},
                                        {GetChainCode, &ExtKeyVarInterface::getChainCode},
                                        {VerifyCompactSignatureWithHash, &ExtKeyVarInterface::verifyCompactSignatureWithHash},
                                        {IsPrivate, &ExtKeyVarInterface::isPrivate}};


Poco::Dynamic::Var ExtKeyVarInterface::fromSeed(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto seed = _deserializer.deserialize<core::Buffer>(argsArr->get(0), "seed");
    auto extKey = crypto::ExtKey::fromSeed(seed);
    auto service = new ExtKeyVarInterface(extKey, getSerializerOptions());
    return (int64_t)service;
}

Poco::Dynamic::Var ExtKeyVarInterface::fromBase58(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto base58 = _deserializer.deserialize<std::string>(argsArr->get(0), "base58");
    auto extKey = crypto::ExtKey::fromBase58(base58);
    auto service = new ExtKeyVarInterface(extKey, getSerializerOptions());
    return (int64_t)service;
}

Poco::Dynamic::Var ExtKeyVarInterface::generateRandom(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    auto extKey = crypto::ExtKey::generateRandom();
    auto service = new ExtKeyVarInterface(extKey, getSerializerOptions());
    return (int64_t)service;
}

Poco::Dynamic::Var ExtKeyVarInterface::derive(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto index = _deserializer.deserialize<int64_t>(argsArr->get(0), "index");
    auto extKey = _extKey.derive(index);
    auto service = new ExtKeyVarInterface(extKey, getSerializerOptions());
    return (int64_t)service;
}

Poco::Dynamic::Var ExtKeyVarInterface::deriveHardened(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto index = _deserializer.deserialize<int64_t>(argsArr->get(0), "index");
    auto extKey = _extKey.deriveHardened(index);
    auto service = new ExtKeyVarInterface(extKey, getSerializerOptions());
    return (int64_t)service;
}

Poco::Dynamic::Var ExtKeyVarInterface::getPrivatePartAsBase58(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    auto result = _extKey.getPrivatePartAsBase58();
    return _serializer.serialize(result);
}

Poco::Dynamic::Var ExtKeyVarInterface::getPublicPartAsBase58(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    auto result = _extKey.getPublicPartAsBase58();
    return _serializer.serialize(result);
}

Poco::Dynamic::Var ExtKeyVarInterface::getPublicKey(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    auto result = _extKey.getPublicKey();
    return _serializer.serialize(result);
}

Poco::Dynamic::Var ExtKeyVarInterface::getPrivateKey(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    auto result = _extKey.getPrivateKey();
    return _serializer.serialize(result);
}

Poco::Dynamic::Var ExtKeyVarInterface::getPrivateEncKey(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    auto result = _extKey.getPrivateEncKey();
    return _serializer.serialize(result);
}

Poco::Dynamic::Var ExtKeyVarInterface::getPublicKeyAsBase58Address(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    auto result = _extKey.getPublicKeyAsBase58Address();
    return _serializer.serialize(result);
}

Poco::Dynamic::Var ExtKeyVarInterface::getChainCode(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    auto result = _extKey.getChainCode();
    return _serializer.serialize(result);
}

Poco::Dynamic::Var ExtKeyVarInterface::verifyCompactSignatureWithHash(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto message = _deserializer.deserialize<core::Buffer>(argsArr->get(0), "message");
    auto signature = _deserializer.deserialize<core::Buffer>(argsArr->get(1), "signature");
    auto result = _extKey.verifyCompactSignatureWithHash(message, signature);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var ExtKeyVarInterface::isPrivate(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    auto result = _extKey.isPrivate();
    return _serializer.serialize(result);
}

Poco::Dynamic::Var ExtKeyVarInterface::exec(METHOD method, const Poco::Dynamic::Var& args) {
    auto it = methodMap.find(method);
    if (it == methodMap.end()) {
        throw core::InvalidMethodException();
    }
    return (*this.*(it->second))(args);
}
