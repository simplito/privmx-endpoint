/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_UTILSVARINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_UTILSVARINTERFACE_HPP_

#include <Poco/Dynamic/Var.h>

#include "privmx/endpoint/core/Utils.hpp"
#include "privmx/endpoint/core/VarDeserializer.hpp"
#include "privmx/endpoint/core/VarSerializer.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class UtilsVarInterface {
public:
    enum METHOD {
        EncodeHex = 1,
        DecodeHex = 2,
        IsHex = 3,
        EncodeBase32 = 4,
        DecodeBase32 = 5,
        IsBase32 = 6,
        EncodeBase64 = 7,
        DecodeBase64 = 8,
        IsBase64 = 9,
        Trim = 10,
        Split = 11,
        Ltrim = 12,
        Rtrim = 13,
    };
    

    UtilsVarInterface(const core::VarSerializer& serializer)
        : _serializer(serializer) {}


    Poco::Dynamic::Var encodeHex(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var decodeHex(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var isHex(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var encodeBase32(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var decodeBase32(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var isBase32(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var encodeBase64(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var decodeBase64(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var isBase64(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var trim(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var split(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var ltrim(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var rtrim(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var exec(METHOD method, const Poco::Dynamic::Var& args);

private:
    static std::map<METHOD, Poco::Dynamic::Var (UtilsVarInterface::*)(const Poco::Dynamic::Var&)> methodMap;
    core::VarDeserializer _deserializer;
    core::VarSerializer _serializer;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_UTILSVARINTERFACE_HPP_
