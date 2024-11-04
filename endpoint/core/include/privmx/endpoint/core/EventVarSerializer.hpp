/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

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
