/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/store/cache/CacheBackendInMemory.hpp>

namespace privmx {
namespace endpoint {
namespace store {

namespace {

class IteratorImpl : public CacheBackendInterface::Iterator {
public:
    using MapIterator = std::map<std::string, core::Buffer>::iterator;

    IteratorImpl(MapIterator cur, MapIterator end) : _cur(cur), _end(end) {}

    bool valid() const override { return _cur != _end; }

    void next() override { ++_cur; }

    const std::string& key() const override { return _cur->first; }

    core::Buffer value() const override { return _cur->second; }

private:
    MapIterator _cur;
    MapIterator _end;
};

} // namespace

std::optional<core::Buffer> CacheBackendInMemory::get(const std::string& key) {
    auto it = _store.find(key);
    if (it == _store.end()) {
        return std::nullopt;
    }
    return it->second;
}

void CacheBackendInMemory::put(const std::string& key, const core::Buffer& value) {
    _store[key] = value;
}

void CacheBackendInMemory::del(const std::string& key) {
    _store.erase(key);
}

void CacheBackendInMemory::clear() {
    _store.clear();
}

std::unique_ptr<CacheBackendInterface::Iterator> CacheBackendInMemory::seek(const std::string& prefix) {
    auto begin = prefix.empty() ? _store.begin() : _store.lower_bound(prefix);
    return std::make_unique<IteratorImpl>(begin, _store.end());
}

} // namespace store
} // namespace endpoint
} // namespace privmx
