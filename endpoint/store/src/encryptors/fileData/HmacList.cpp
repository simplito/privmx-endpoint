/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#include "privmx/endpoint/store/encryptors/fileData/HmacList.hpp"
#include <privmx/endpoint/store/StoreException.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

HmacList::HmacList(
    const std::string& topHashKey,
    const std::string& topHash,
    const std::string& hashes,
    FileCipher cipher
)
    : _topHashKey(topHashKey), _hashes(hashes), _cipher(cipher) {
    _topHash = _cipher.topHash(_topHashKey, _hashes);
    if (_topHash != topHash) {
        throw InvalidFileTopHashException();
    }
    if (_hashes.size() % _cipher.hashLength() != 0) {
        throw InvalidHashSizeException();
    }
    _size = _hashes.size() / _cipher.hashLength();
}

void HmacList::sync(const std::string& topHashKey, const std::string& topHash, const std::string& hashes) {
    auto tmp = _cipher.topHash(topHashKey, hashes);
    if (tmp != topHash) {
        throw InvalidFileTopHashException();
    }
    if (hashes.size() % _cipher.hashLength() != 0) {
        throw InvalidHashSizeException();
    }
    _topHashKey = topHashKey;
    _hashes = hashes;
    _topHash = tmp;
    _size = _hashes.size() / _cipher.hashLength();
}

void HmacList::setAll(const std::string& hashes) {
    if (hashes.size() % _cipher.hashLength() != 0) {
        throw InvalidHashSizeException();
    }
    _hashes = hashes;
    _topHash.reset();
    _size = _hashes.size() / _cipher.hashLength();
}

void HmacList::set(const uint64_t& chunkIndex, const std::string& hash, bool truncate) {
    const auto hashLength = _cipher.hashLength();
    if (hash.size() != hashLength) {
        throw InvalidHashSizeException();
    }
    if (chunkIndex < _size) {
        auto offset = chunkIndex * hashLength;
        std::memcpy(_hashes.data() + offset, hash.data(), hashLength);
        if (truncate) {
            _size = chunkIndex + 1;
            _hashes.erase(offset + hashLength);
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
    return _hashes.substr(chunkIndex * _cipher.hashLength(), _cipher.hashLength());
}

const std::string& HmacList::getAll() {
    return _hashes;
}

const std::string& HmacList::getTopHash() {
    if (!_topHash.has_value()) {
        _topHash = _cipher.topHash(_topHashKey, _hashes);
    }
    return _topHash.value();
}

bool HmacList::verifyHash(const uint64_t& chunkIndex, const std::string& hash) {
    return getHash(chunkIndex) == hash;
}

bool HmacList::verifyTopHash(const std::string& topHash) {
    return getTopHash() == topHash;
}
