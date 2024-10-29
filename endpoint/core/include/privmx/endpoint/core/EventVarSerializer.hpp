#ifndef _PRIVMXLIB_ENDPOINT_CORE_EVENTVARSERIALIZER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_EVENTVARSERIALIZER_HPP_

#include <Poco/Dynamic/Var.h>

#include <memory>

#include "privmx/endpoint/core/VarSerializer.hpp"

namespace privmx {
namespace endpoint {
namespace core {

struct SerializedEvent {
    Poco::Dynamic::Var value;
};

class EventVarSerializer {
public:
    static std::shared_ptr<VarSerializer> getInstance();

private:
    static std::shared_ptr<VarSerializer> _serializer;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_EVENTVARSERIALIZER_HPP_
