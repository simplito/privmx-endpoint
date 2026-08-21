/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_CACHE_SLRU_BACKED_CACHE_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_CACHE_SLRU_BACKED_CACHE_HPP_

#include <cstdint>
#include <optional>
#include <string>
#include <tuple>

#include <privmx/endpoint/store/cache/CacheBackendInterface.hpp>
#include <privmx/endpoint/store/cache/CacheInterface.hpp>
#include <privmx/endpoint/store/cache/SlruPolicy.hpp>

namespace privmx {
namespace endpoint {
namespace store {

/**
 * CacheInterface implementation backed by a persistent CacheBackendInterface,
 * with a configurable size cap and SLRU eviction.
 *
 * Both cached values and SLRU metadata are stored in the backend, so eviction
 * order and segment membership survive process restarts. On construction the
 * SLRU state is restored by reading the metadata from the backend.
 *
 * Internal backend key layout (invisible to callers):
 *   "d;"    + user_key →  raw cached value
 *   "slru;" + user_key →  17-byte metadata: [seq: uint64_le][size: uint64_le][segment: uint8]
 *
 * Both prefixes use ';' which never appears in UUIDs, Base58, or Base64,
 * so data keys and metadata keys never collide with each other or with external entries.
 */
class SlruBackedCache : public CacheInterface {
public:
    static constexpr double DEFAULT_PROTECTED_RATIO = 0.8;

    explicit SlruBackedCache(
        CacheBackendInterface& backend,
        size_t maxBytes = CacheBackendInterface::DEFAULT_MAX_BYTES,
        double protectedRatio = DEFAULT_PROTECTED_RATIO
    );

    std::optional<core::Buffer> get(const std::string& key) override;
    void put(const std::string& key, const core::Buffer& data) override;
    void del(const std::string& key) override;

private:
    static constexpr const char* DATA_PREFIX = "d;";
    static constexpr const char* META_PREFIX = "slru;";

    static std::string dataKey(const std::string& key);
    static std::string metaKey(const std::string& key);
    static core::Buffer encodeMeta(uint64_t seq, uint64_t size, Segment segment);
    static std::tuple<uint64_t, uint64_t, Segment> decodeMeta(const core::Buffer& raw);

    void loadFromBackend();
    void persistMeta(const std::string& key, size_t size, Segment segment);
    void evictUntilFit(size_t incomingSize);

    CacheBackendInterface& _backend;
    size_t _maxBytes;
    uint64_t _seq = 0;
    SlruPolicy _slru;
};

} // namespace store
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_CACHE_SLRU_BACKED_CACHE_HPP_
