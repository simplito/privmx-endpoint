/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_HASHLIST_INTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_HASHLIST_INTERFACE_HPP_

namespace privmx {
namespace endpoint {
namespace store {

#include <cstdint>
#include <string>

class IHashList
{
public:

    virtual ~IHashList() = default;
    virtual void set(const int64_t& chunkIndex, const std::string& hash) = 0;
    virtual const std::string getHash(const int64_t& chunkIndex) = 0;
    virtual const std::string& getAll() = 0;
    virtual const std::string& getTopHash() = 0;
    virtual bool verifyHash(const int64_t& chunkIndex, const std::string& hash) = 0;
    virtual bool verifyTopHash(const std::string& topHash) = 0;
    virtual size_t getHashSize() = 0;
    // virtual int64_t getAllSize() = 0;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_HASHLIST_INTERFACE_HPP_
