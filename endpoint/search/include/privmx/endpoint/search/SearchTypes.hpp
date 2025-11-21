/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_SEARCH_SEARCHTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_SEARCH_SEARCHTYPES_HPP_

#include <string>

#include "privmx/endpoint/core/Connection.hpp"
#include "privmx/endpoint/store/StoreApi.hpp"
#include "privmx/endpoint/kvdb/KvdbApi.hpp"

namespace privmx {
namespace endpoint {
namespace search {

struct PrivmxSession
{
    std::string id;
    privmx::endpoint::core::Connection connection;
    privmx::endpoint::store::StoreApi storeApi;
    privmx::endpoint::kvdb::KvdbApi kvdbApi;
    std::string kvdbId;
    std::string storeId;
};

} // search
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_SEARCH_SEARCHTYPES_HPP_
