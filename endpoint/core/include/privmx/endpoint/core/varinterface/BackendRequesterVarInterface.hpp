#ifndef _PRIVMXLIB_ENDPOINT_CORE_BACKENDREQUESTERVARINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_BACKENDREQUESTERVARINTERFACE_HPP_

#include <Poco/Dynamic/Var.h>

#include "privmx/endpoint/core/BackendRequester.hpp"
#include "privmx/endpoint/core/VarDeserializer.hpp"
#include "privmx/endpoint/core/VarSerializer.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class BackendRequesterVarInterface {
public:
    enum METHOD {
        BackendRequest = 0
    };

    BackendRequesterVarInterface(const core::VarSerializer& serializer)
        : _serializer(serializer) {}

    Poco::Dynamic::Var backendRequest(const Poco::Dynamic::Var& args);

    Poco::Dynamic::Var exec(METHOD method, const Poco::Dynamic::Var& args);
private:
    static std::map<METHOD, Poco::Dynamic::Var (BackendRequesterVarInterface::*)(const Poco::Dynamic::Var&)> methodMap;

    core::VarDeserializer _deserializer;
    core::VarSerializer _serializer;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_BACKENDREQUESTERVARINTERFACE_HPP_
