/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/store/cache/SlruPolicy.hpp>

namespace privmx {
namespace endpoint {
namespace store {

SlruPolicy::SlruPolicy(size_t maxBytes, double protectedRatio) {
    _protected.maxBytes = static_cast<size_t>(maxBytes * protectedRatio);
    _probationary.maxBytes = maxBytes - _protected.maxBytes;
}

void SlruPolicy::insertHead(SegmentState& seg, const std::string& key, size_t size) {
    seg.list.push_front({key, size});
    seg.index[key] = seg.list.begin();
    seg.totalSize += size;
}

void SlruPolicy::removeFrom(
    SegmentState& seg,
    std::unordered_map<std::string, std::list<Entry>::iterator>::iterator indexIt
) {
    seg.totalSize -= indexIt->second->size;
    seg.list.erase(indexIt->second);
    seg.index.erase(indexIt);
}

void SlruPolicy::rebalanceProtected() {
    while (_protected.totalSize > _protected.maxBytes && !_protected.list.empty()) {
        Entry tail = _protected.list.back();
        removeFrom(_protected, _protected.index.find(tail.key));
        insertHead(_probationary, tail.key, tail.size);
    }
}

Segment SlruPolicy::touch(const std::string& key, size_t size) {
    {
        auto it = _protected.index.find(key);
        if (it != _protected.index.end()) {
            removeFrom(_protected, it);
            insertHead(_protected, key, size);
            return Segment::Protected;
        }
    }
    {
        auto it = _probationary.index.find(key);
        if (it != _probationary.index.end()) {
            removeFrom(_probationary, it);
            insertHead(_protected, key, size);
            rebalanceProtected();
            return Segment::Protected;
        }
    }
    insertHead(_probationary, key, size);
    return Segment::Probationary;
}

void SlruPolicy::restore(const std::string& key, size_t size, Segment segment) {
    if (segment == Segment::Protected) {
        insertHead(_protected, key, size);
    } else {
        insertHead(_probationary, key, size);
    }
}

std::optional<SlruPolicy::Entry> SlruPolicy::evictOne() {
    if (!_probationary.list.empty()) {
        Entry entry = _probationary.list.back();
        removeFrom(_probationary, _probationary.index.find(entry.key));
        return entry;
    }
    if (!_protected.list.empty()) {
        Entry entry = _protected.list.back();
        removeFrom(_protected, _protected.index.find(entry.key));
        return entry;
    }
    return std::nullopt;
}

void SlruPolicy::remove(const std::string& key) {
    {
        auto it = _protected.index.find(key);
        if (it != _protected.index.end()) {
            removeFrom(_protected, it);
            return;
        }
    }
    {
        auto it = _probationary.index.find(key);
        if (it != _probationary.index.end()) {
            removeFrom(_probationary, it);
        }
    }
}

bool SlruPolicy::contains(const std::string& key) const {
    return _protected.index.count(key) || _probationary.index.count(key);
}

size_t SlruPolicy::totalSize() const {
    return _protected.totalSize + _probationary.totalSize;
}

bool SlruPolicy::empty() const {
    return _probationary.list.empty() && _protected.list.empty();
}

} // namespace store
} // namespace endpoint
} // namespace privmx
