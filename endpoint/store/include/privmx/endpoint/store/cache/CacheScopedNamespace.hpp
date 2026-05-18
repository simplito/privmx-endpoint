/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_CACHE_SCOPED_NAMESPACE_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_CACHE_SCOPED_NAMESPACE_HPP_

#include <memory>
#include <string>
#include <privmx/endpoint/store/cache/CacheInterface.hpp>

namespace privmx {
namespace endpoint {
namespace store {

/**
 * Wraps a shared CacheInterface instance and prepends a fixed prefix to every key,
 * providing namespace isolation between different Bridge URLs and users
 * without requiring separate cache instances.
 */
class CacheScopedNamespace : public CacheInterface
{
public:
    CacheScopedNamespace(std::string prefix, std::shared_ptr<CacheInterface> inner)
        : _prefix(std::move(prefix)), _inner(std::move(inner)) {}

    std::optional<Pson::BinaryString> get(const std::string& key) override {
        return _inner->get(_prefix + key);
    }

    void put(const std::string& key, Pson::BinaryString data) override {
        _inner->put(_prefix + key, std::move(data));
    }

    void del(const std::string& key) override {
        _inner->del(_prefix + key);
    }

private:
    std::string _prefix;
    std::shared_ptr<CacheInterface> _inner;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_CACHE_SCOPED_NAMESPACE_HPP_