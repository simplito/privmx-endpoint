/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_VARINTERFACEUTIL_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_VARINTERFACEUTIL_HPP_

#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Array.h>

namespace privmx {
namespace endpoint {
namespace core {

class VarInterfaceUtil {
public:
    static Poco::JSON::Array::Ptr validateAndExtractArray(const Poco::Dynamic::Var& args, std::size_t size);
    static Poco::JSON::Array::Ptr validateAndExtractArray(const Poco::Dynamic::Var& args, std::size_t minSize,
                                                          std::size_t maxSize);
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_VARINTERFACEUTIL_HPP_
