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
    HmacList(const std::string& topHashKey, const std::string& data = std::string());
    void set(const int64_t& chunkIndex, const std::string& hash);
    const std::string getHash(const int64_t& chunkIndex);
    const std::string& getAll();
    const std::string& getTopHash();
    bool verifyHash(const int64_t& chunkIndex, const std::string& hash);
    bool verifyTopHash(const std::string& topHash);
    inline size_t getHashSize() { return HMAC_SIZE; };

private:
    std::string _topHashKey;
    std::optional<std::string> _topHash;
    int64_t _size = 0;
    std::string _hashes;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_HMACLIST_HPP_
