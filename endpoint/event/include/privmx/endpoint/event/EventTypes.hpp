/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_EVENT_EVENTTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_EVENT_EVENTTYPES_HPP_

#include <optional>
#include <string>

#include "privmx/endpoint/core/Buffer.hpp"

namespace privmx {
namespace endpoint {
namespace event {

struct InternalContextEventDataV1 {
    std::string type;
    privmx::endpoint::core::Buffer data;
};

struct DecryptedInternalContextEventDataV1 :  public InternalContextEventDataV1, public core::DecryptedVersionedData {};
struct DecryptedContextEventDataV1 :  public core::DecryptedVersionedData {
    privmx::endpoint::core::Buffer data;
};

struct DecryptedEventEncKeyV1 : public core::DecryptedVersionedData {
    std::string key;
};

enum EventType {
    LIB_INTERNAL = 0,
    LIB_API = 1
};

struct ContextEventDataV5 {
    privmx::endpoint::core::Buffer data;
    std::optional<std::string> type;
    core::DataIntegrityObject dio;
};

struct ContextEventDataToEncryptV5 : public ContextEventDataV5 {};
struct DecryptedEventDataV5 : public ContextEventDataV5, public core::DecryptedVersionedData {};

}  // namespace event
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_EVENT_EVENTTYPES_HPP_
