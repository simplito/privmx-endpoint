/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_CORETYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CORETYPES_HPP_

#include <optional>
#include <string>

#include "privmx/endpoint/core/Buffer.hpp"

namespace privmx {
namespace endpoint {
namespace core {

struct EncKey {
    std::string id;
    std::string key;
};


}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_CORETYPES_HPP_
