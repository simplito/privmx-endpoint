/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_CACHE_INTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_CACHE_INTERFACE_HPP_

#include <string>
#include <optional>
#include <Pson/BinaryString.hpp>

namespace privmx {
namespace endpoint {
namespace store {

class CacheInterface
{
public:
    virtual ~CacheInterface() = default;
    virtual std::optional<Pson::BinaryString> get(const std::string& key) = 0;
    virtual void put(const std::string& key, Pson::BinaryString data) = 0;
    virtual void del(const std::string& key) = 0;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_CACHE_INTERFACE_HPP_
