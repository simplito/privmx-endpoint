/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_HMACLIST_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_HMACLIST_HPP_

#include <cstring>
#include <optional>

#include <privmx/crypto/Crypto.hpp>
#include "privmx/endpoint/store/interfaces/IHashList.hpp"

namespace privmx {
namespace endpoint {
namespace store {

class HmacList : public IHashList
{
public:
    HmacList(const std::string& topHashKey, const std::string& data = std::string()) : _topHashKey(topHashKey), _hashes(data) {
        if (_hashes.size() % HMAC_SIZE != 0) {
            // TODO: throw;
        }
        _size = _hashes.size() / HMAC_SIZE;
    }
    void set(const int64_t& chunkIndex, const std::string& hash) {
        if (hash.size() != HMAC_SIZE) {
            // TODO: throw;
        }
        if (chunkIndex < size) {
            auto offset = chunkIndex * HMAC_SIZE;
            std::memcpy(_hashes.data() + offset, hash.data(), HMAC_SIZE);
            _topHash.reset();
        } else if (chunkIndex <= size) {
            _size += 1;
            _hashes.append(hash);
            _topHash.reset();
        }
        // TODO: throw;
    }
    const std::string& getHash(const int64_t& chunkIndex) {
        if (chunkIndex > size) {
            // TODO: throw;
        }
        return _hashes.substr(chunkIndex * HMAC_SIZE, HMAC_SIZE);
    }
    const std::string& getAll() {
        return _hashes;
    }
    const std::string& getTopHash() {
        if (!_topHash.has_value()) {
            _topHash = privmx::crypto::hmacSha256(_topHashKey, _hashes);
        }
        return _topHash.value();
    }
    bool verifyHash(const int64_t& chunkIndex, const std::string& hash) {
        return getHash(chunkIndex) == hash;
    }
    bool verifyTopHash(const std::string& topHash) {
        return getTopHash() == topHash;
    };
    size_t getHashSize() { return HMAC_SIZE; };

private:
    constexpr static size_t HMAC_SIZE = 32;
    std::string _topHashKey;
    std::optional<std::string> _topHash;
    int64_t _size = 0;
    std::string _hashes;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_HMACLIST_HPP_
