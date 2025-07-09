/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#include <privmx/crypto/Crypto.hpp>
#include <privmx/endpoint/store/StoreException.hpp>
#include "privmx/endpoint/store/encryptors/fileData/HmacList.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

HmacList::HmacList(const std::string& topHashKey, const std::string& data) : _topHashKey(topHashKey), _hashes(data) {
    if (_hashes.size() % HMAC_SIZE != 0) {
        // throw InvalidHashSizeException();
    }
    _size = _hashes.size() / HMAC_SIZE;
}

void HmacList::set(const int64_t& chunkIndex, const std::string& hash) {
    if (hash.size() != HMAC_SIZE) {
        throw InvalidHashSizeException();
    }
    if (chunkIndex < _size) {
        auto offset = chunkIndex * HMAC_SIZE;
        std::memcpy(_hashes.data() + offset, hash.data(), HMAC_SIZE);
        _topHash.reset();
    } else if (chunkIndex == _size) {
        _size += 1;
        _hashes.append(hash);
        _topHash.reset();
    } else {
        throw HashIndexOutOfBoundsException();
    }
}

const std::string HmacList::getHash(const int64_t& chunkIndex) {
    if (chunkIndex > _size) {
        throw HashIndexOutOfBoundsException();
    }
    return _hashes.substr(chunkIndex * HMAC_SIZE, HMAC_SIZE);
}

const std::string& HmacList::getAll() {
    return _hashes;
}

const std::string& HmacList::getTopHash() {
    if (!_topHash.has_value()) {
        _topHash = privmx::crypto::Crypto::hmacSha256(_topHashKey, _hashes);
    }
    return _topHash.value();
}

bool HmacList::verifyHash(const int64_t& chunkIndex, const std::string& hash) {
    return getHash(chunkIndex) == hash;
}

bool HmacList::verifyTopHash(const std::string& topHash) {
    return getTopHash() == topHash;
}