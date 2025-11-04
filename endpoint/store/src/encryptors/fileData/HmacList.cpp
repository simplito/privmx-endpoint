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

HmacList::HmacList(const std::string& topHashKey, const std::string& topHash, const std::string& hashes) : _topHashKey(topHashKey), _hashes(hashes) {
    _topHash = privmx::crypto::Crypto::hmacSha256(_topHashKey, _hashes);
    if(_topHash != topHash) {
        throw InvalidFileTopHashException();
    }
    if (_hashes.size() % HMAC_SIZE != 0) {
        throw InvalidHashSizeException();
    }
    _size = _hashes.size() / HMAC_SIZE;
}

void HmacList::sync(const std::string& topHashKey, const std::string& topHash, const std::string& hashes) {
    auto tmp = privmx::crypto::Crypto::hmacSha256(topHashKey, hashes);
    if(tmp != topHash) {
        throw InvalidFileTopHashException();
    }
    if (hashes.size() % HMAC_SIZE != 0) {
        throw InvalidHashSizeException();
    }
    _topHashKey = topHashKey;
    _hashes = hashes;
    _topHash = tmp;
    _size = _hashes.size() / HMAC_SIZE;
}

void HmacList::setAll(const std::string& hashes) {
    if (hashes.size() % HMAC_SIZE != 0) {
        throw InvalidHashSizeException();
    }
    _hashes = hashes;
    _topHash.reset();
    _size = _hashes.size() / HMAC_SIZE;
}


void HmacList::set(const uint64_t& chunkIndex, const std::string& hash, bool truncate ) {
    if (hash.size() != HMAC_SIZE) {
        throw InvalidHashSizeException();
    }
    if (chunkIndex < _size) {
        auto offset = chunkIndex * HMAC_SIZE;
        std::memcpy(_hashes.data() + offset, hash.data(), HMAC_SIZE);
        if(truncate) {
            _size = chunkIndex+1;
            _hashes.erase(offset+HMAC_SIZE);
        }
        _topHash.reset();
    } else if (chunkIndex == _size) {
        _size += 1;
        _hashes.append(hash);
        _topHash.reset();
    } else {
        throw HashIndexOutOfBoundsException();
    }
}

const std::string HmacList::getHash(const uint64_t& chunkIndex) {
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

bool HmacList::verifyHash(const uint64_t& chunkIndex, const std::string& hash) {
    return getHash(chunkIndex) == hash;
}

bool HmacList::verifyTopHash(const std::string& topHash) {
    return getTopHash() == topHash;
}