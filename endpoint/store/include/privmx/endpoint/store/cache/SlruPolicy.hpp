/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_CACHE_SLRU_POLICY_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_CACHE_SLRU_POLICY_HPP_

#include <cstdint>
#include <list>
#include <optional>
#include <string>
#include <unordered_map>

namespace privmx {
namespace endpoint {
namespace store {

enum class Segment : uint8_t {
    Probationary = 0,
    Protected = 1
};

/**
 * In-memory Segmented LRU (SLRU) eviction policy tracker.
 *
 * Entries live in one of two segments:
 *   - Probationary: newly inserted or demoted entries; eviction target.
 *   - Protected:    entries promoted after a second access; shielded from eviction.
 *
 * On touch:
 *   - New entry           → head of Probationary
 *   - Probationary hit    → promoted to head of Protected;
 *                           if Protected overflows its budget, its LRU tail
 *                           is demoted to head of Probationary
 *   - Protected hit       → moved to head of Protected
 *
 * evictOne() always targets the tail of Probationary; if Probationary is
 * empty it falls back to the tail of Protected.
 *
 * All operations are O(1).
 */
class SlruPolicy {
public:
    struct Entry {
        std::string key;
        size_t size;
    };

    /**
     * @param maxBytes       Total byte budget for both segments combined.
     * @param protectedRatio Fraction of maxBytes reserved for the Protected segment [0, 1].
     */
    explicit SlruPolicy(size_t maxBytes, double protectedRatio = 0.8);

    /**
     * Marks @p key as most-recently-used, applying promotion logic.
     * Returns the segment the key ended up in.
     */
    Segment touch(const std::string& key, size_t size);

    /**
     * Inserts @p key directly into @p segment without triggering promotion.
     * Used when restoring persisted state on startup.
     */
    void restore(const std::string& key, size_t size, Segment segment);

    /**
     * Removes and returns the eviction candidate (tail of Probationary,
     * or tail of Protected if Probationary is empty).
     * Returns std::nullopt if both segments are empty.
     */
    std::optional<Entry> evictOne();

    void remove(const std::string& key);
    bool contains(const std::string& key) const;
    size_t totalSize() const;
    bool empty() const;

private:
    struct SegmentState {
        std::list<Entry> list; // front = MRU, back = LRU
        std::unordered_map<std::string, std::list<Entry>::iterator> index;
        size_t totalSize = 0;
        size_t maxBytes = 0;
    };

    void insertHead(SegmentState& seg, const std::string& key, size_t size);
    void removeFrom(SegmentState& seg, std::unordered_map<std::string, std::list<Entry>::iterator>::iterator indexIt);
    void rebalanceProtected();

    SegmentState _probationary;
    SegmentState _protected;
};

} // namespace store
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_CACHE_SLRU_POLICY_HPP_
