/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/store/cache/SlruBackedCache.hpp>

#include <algorithm>
#include <cstring>
#include <vector>

namespace privmx {
namespace endpoint {
namespace store {

SlruBackedCache::SlruBackedCache(CacheBackendInterface& backend, size_t maxBytes, double protectedRatio)
        : _backend(backend), _maxBytes(maxBytes), _slru(maxBytes, protectedRatio) {
    loadFromBackend();
}

std::optional<core::Buffer> SlruBackedCache::get(const std::string& key) {
    auto data = _backend.get(dataKey(key));
    if (!data) return std::nullopt;
    size_t size = data->size();
    auto seg = _slru.touch(key, size);
    persistMeta(key, size, seg);
    return data;
}

void SlruBackedCache::put(const std::string& key, const core::Buffer& data) {
    size_t newSize = data.size();
    _slru.remove(key);
    evictUntilFit(newSize);
    _backend.put(dataKey(key), data);
    auto seg = _slru.touch(key, newSize);
    persistMeta(key, newSize, seg);
}

void SlruBackedCache::del(const std::string& key) {
    _slru.remove(key);
    _backend.del(dataKey(key));
    _backend.del(metaKey(key));
}

// --- private ---

std::string SlruBackedCache::dataKey(const std::string& key) {
    return std::string(DATA_PREFIX) + key;
}

std::string SlruBackedCache::metaKey(const std::string& key) {
    return std::string(META_PREFIX) + key;
}

core::Buffer SlruBackedCache::encodeMeta(uint64_t seq, uint64_t size, Segment segment) {
    char buf[17];
    std::memcpy(buf, &seq, 8);
    std::memcpy(buf + 8, &size, 8);
    buf[16] = static_cast<char>(segment);
    return core::Buffer::from(buf, 17);
}

std::tuple<uint64_t, uint64_t, Segment> SlruBackedCache::decodeMeta(const core::Buffer& raw) {
    if (raw.size() < 17) return {0, 0, Segment::Probationary};
    uint64_t seq = 0, size = 0;
    std::memcpy(&seq, raw.data(), 8);
    std::memcpy(&size, raw.data() + 8, 8);
    auto seg = static_cast<Segment>(static_cast<uint8_t>(raw.data()[16]));
    return {seq, size, seg};
}

void SlruBackedCache::loadFromBackend() {
    using Record = std::tuple<uint64_t, std::string, size_t, Segment>;
    std::vector<Record> records;
    std::vector<std::string> orphanedMetaKeys;

    const std::string metaSeekPrefix(META_PREFIX);
    auto it = _backend.seek(metaSeekPrefix);
    while (it->valid() && it->key().compare(0, metaSeekPrefix.size(), metaSeekPrefix) == 0) {
        std::string userKey = it->key().substr(metaSeekPrefix.size());
        auto [seq, size, seg] = decodeMeta(it->value());

        if (_backend.get(dataKey(userKey))) {
            records.emplace_back(seq, std::move(userKey), static_cast<size_t>(size), seg);
            if (seq > _seq) _seq = seq;
        } else {
            orphanedMetaKeys.push_back(it->key());
        }
        it->next();
    }

    for (const auto& k : orphanedMetaKeys) {
        _backend.del(k);
    }

    // Sort ascending by seq so restore() ends with the MRU entry at each segment's head.
    std::sort(records.begin(), records.end());

    for (auto& [seq, key, size, seg] : records) {
        _slru.restore(key, size, seg);
    }
}

void SlruBackedCache::persistMeta(const std::string& key, size_t size, Segment segment) {
    ++_seq;
    _backend.put(metaKey(key), encodeMeta(_seq, static_cast<uint64_t>(size), segment));
}

void SlruBackedCache::evictUntilFit(size_t incomingSize) {
    while (!_slru.empty() && _slru.totalSize() + incomingSize > _maxBytes) {
        auto evicted = _slru.evictOne();
        if (!evicted) break;
        _backend.del(dataKey(evicted->key));
        _backend.del(metaKey(evicted->key));
    }
}

} // namespace store
} // namespace endpoint
} // namespace privmx
