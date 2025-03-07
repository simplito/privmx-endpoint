/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_CONTEXTPROVIDER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CONTEXTPROVIDER_HPP_

#include <privmx/endpoint/core/ContainerProvider.hpp>
#include "privmx/endpoint/core/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class ContextProvider : public core::ContainerProvider<std::string, server::ContextInfo> {
public:
    ContextProvider(std::function<server::ContextInfo(std::string)> getThread);
    void updateByValue(const server::ContextInfo& container) override;
};

} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_CONTEXTPROVIDER_HPP_