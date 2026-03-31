/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_SEARCH_LOCKSESSION_HPP_
#define _PRIVMXLIB_ENDPOINT_SEARCH_LOCKSESSION_HPP_

#include <memory>
#include <string>
#include <vector>

#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/search/DynamicTypes.hpp"
#include "privmx/endpoint/search/SearchTypes.hpp"
#include "privmx/endpoint/search/LockSetLogic.hpp"
#include "privmx/endpoint/kvdb/KvdbApi.hpp"

namespace privmx {
namespace endpoint {
namespace search {

class LockSession
{
public:
    LockSession(kvdb::KvdbApi kvdbApi, const std::string& kvdbId, const std::string& filepath);
    bool lock(LockLevel level);
    bool unlock(LockLevel level);
    bool checkReservedLock();
    static void destroyLock(kvdb::KvdbApi kvdbApi, std::string kvdbId, std::string filepath);

private:
    static const std::string _KVDB_PREFIX;
    static const core::Buffer _META;

    void getLockSetFromKvdb();
    void setLockSetInKvdb();

    kvdb::KvdbApi _kvdbApi;
    std::string _kvdbId;
    std::string _filepath;
    LockSetLogic _lockSet;
    int64_t _version;
};

}  // namespace search
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_SEARCH_LOCKSESSION_HPP_
