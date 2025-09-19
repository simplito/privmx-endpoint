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

#include <cstdint>
#include <string>
#include <optional>
#include "privmx/endpoint/store/StoreTypes.hpp"
#include "privmx/endpoint/store/interfaces/IHashList.hpp"

namespace privmx {
namespace endpoint {
namespace store {

class HmacList : public IHashList
{
public:
    HmacList(const std::string& topHashKey, const std::string& topHash, const std::string& hashes = std::string());
    virtual void sync(const std::string& topHashKey, const std::string& topHash, const std::string& hashes) override;
    virtual void setAll(const std::string& hashes) override;
    virtual void set(const uint64_t& chunkIndex, const std::string& hash, bool truncate = false) override;
    virtual const std::string getHash(const uint64_t& chunkIndex) override;
    virtual const std::string& getAll() override;
    virtual const std::string& getTopHash() override;
    virtual bool verifyHash(const uint64_t& chunkIndex, const std::string& hash) override;
    virtual bool verifyTopHash(const std::string& topHash) override;
    virtual inline uint64_t getHashSize() override { return HMAC_SIZE; };

private:
    std::string _topHashKey;
    std::optional<std::string> _topHash;
    uint64_t _size = 0;
    std::string _hashes;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_HMACLIST_HPP_
