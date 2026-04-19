/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_CACHE_IN_MEMORY_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_CACHE_IN_MEMORY_HPP_

#include <string>
#include <optional>
#include <unordered_map>
#include <Pson/BinaryString.hpp>
#include <privmx/endpoint/store/cache/CacheInterface.hpp>

namespace privmx {
namespace endpoint {
namespace store {

class CacheInMemory : public CacheInterface
{
public:
    std::optional<Pson::BinaryString> get(const std::string& key) override;
    void put(const std::string& key, Pson::BinaryString data) override;
    void del(const std::string& key) override;

private:
    std::unordered_map<std::string, Pson::BinaryString> _store;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_CACHE_IN_MEMORY_HPP_
