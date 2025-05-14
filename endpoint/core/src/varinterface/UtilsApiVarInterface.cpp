/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/varinterface/UtilsVarInterface.hpp"
#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/varinterface/VarInterfaceUtil.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

std::map<UtilsVarInterface::METHOD, Poco::Dynamic::Var (UtilsVarInterface::*)(const Poco::Dynamic::Var&)>
    UtilsVarInterface::methodMap = {{EncodeHex, &UtilsVarInterface::encodeHex},
                                    {DecodeHex, &UtilsVarInterface::decodeHex},
                                    {IsHex, &UtilsVarInterface::isHex},
                                    {EncodeBase32, &UtilsVarInterface::encodeBase32},
                                    {DecodeBase32, &UtilsVarInterface::decodeBase32},
                                    {IsBase32, &UtilsVarInterface::isBase32},
                                    {EncodeBase64, &UtilsVarInterface::encodeBase64},
                                    {DecodeBase64, &UtilsVarInterface::decodeBase64},
                                    {IsBase64, &UtilsVarInterface::isBase64},
                                    {Trim, &UtilsVarInterface::trim},
                                    {Split, &UtilsVarInterface::split},
                                    {Ltrim, &UtilsVarInterface::ltrim},
                                    {Rtrim, &UtilsVarInterface::rtrim}};


Poco::Dynamic::Var UtilsVarInterface::encodeHex(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto data = _deserializer.deserialize<core::Buffer>(argsArr->get(0), "data");
    auto result = Hex::encode(data);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var UtilsVarInterface::decodeHex(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto hex_data = _deserializer.deserialize<std::string>(argsArr->get(0), "hex_data");
    auto result = Hex::decode(hex_data);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var UtilsVarInterface::isHex(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto data = _deserializer.deserialize<std::string>(argsArr->get(0), "data");
    auto result = Hex::is(data);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var UtilsVarInterface::encodeBase32(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto data = _deserializer.deserialize<core::Buffer>(argsArr->get(0), "data");
    auto result = Base32::encode(data);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var UtilsVarInterface::decodeBase32(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto base32_data = _deserializer.deserialize<std::string>(argsArr->get(0), "base32_data");
    auto result = Base32::decode(base32_data);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var UtilsVarInterface::isBase32(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto data = _deserializer.deserialize<std::string>(argsArr->get(0), "data");
    auto result = Base32::is(data);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var UtilsVarInterface::encodeBase64(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto data = _deserializer.deserialize<core::Buffer>(argsArr->get(0), "data");
    auto result = Base64::encode(data);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var UtilsVarInterface::decodeBase64(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto base64_data = _deserializer.deserialize<std::string>(argsArr->get(0), "base64_data");
    auto result = Base64::decode(base64_data);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var UtilsVarInterface::isBase64(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto data = _deserializer.deserialize<std::string>(argsArr->get(0), "data");
    auto result = Base64::is(data);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var UtilsVarInterface::trim(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto data = _deserializer.deserialize<std::string>(argsArr->get(0), "data");
    auto result = Utils::trim(data);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var UtilsVarInterface::split(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto data = _deserializer.deserialize<std::string>(argsArr->get(0), "data");
    auto delimiter = _deserializer.deserialize<std::string>(argsArr->get(1), "delimiter");
    auto result = Utils::split(data, delimiter);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var UtilsVarInterface::ltrim(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto data = _deserializer.deserialize<std::string>(argsArr->get(0), "data");
    Utils::ltrim(data);
    return _serializer.serialize(data);
}

Poco::Dynamic::Var UtilsVarInterface::rtrim(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto data = _deserializer.deserialize<std::string>(argsArr->get(0), "data");
    Utils::rtrim(data);
    return _serializer.serialize(data);
}

Poco::Dynamic::Var UtilsVarInterface::exec(METHOD method, const Poco::Dynamic::Var& args) {
    auto it = methodMap.find(method);
    if (it == methodMap.end()) {
        throw core::InvalidMethodException();
    }
    return (*this.*(it->second))(args);
}
