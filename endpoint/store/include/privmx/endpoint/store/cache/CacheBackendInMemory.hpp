/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_CACHE_BACKEND_IN_MEMORY_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_CACHE_BACKEND_IN_MEMORY_HPP_

#include <map>
#include <memory>
#include <optional>
#include <string>

#include <privmx/endpoint/store/cache/CacheBackendInterface.hpp>

namespace privmx {
namespace endpoint {
namespace store {

class CacheBackendInMemory : public CacheBackendInterface {
public:
    std::optional<core::Buffer> get(const std::string& key) override;
    void put(const std::string& key, const core::Buffer& value) override;
    void del(const std::string& key) override;
    void clear() override;
    std::unique_ptr<Iterator> seek(const std::string& prefix) override;

private:
    std::map<std::string, core::Buffer> _store;
};

} // namespace store
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_CACHE_BACKEND_IN_MEMORY_HPP_
