/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_WEBRTC_VAR_SERIALIZER_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_WEBRTC_VAR_SERIALIZER_HPP_

#include <Poco/Dynamic/Var.h>
#include <privmx/endpoint/core/VarSerializer.hpp>

#include "privmx/endpoint/stream/webrtc/Events.hpp"
#include "privmx/endpoint/stream/webrtc/Types.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamConnectionStateChangedEventData>(
    const stream::StreamConnectionStateChangedEventData& val
);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamConnectionStateChangedEvent>(
    const stream::StreamConnectionStateChangedEvent& val
);

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_WEBRTC_VAR_SERIALIZER_HPP_
