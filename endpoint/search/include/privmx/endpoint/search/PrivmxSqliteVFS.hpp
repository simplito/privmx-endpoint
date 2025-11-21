/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_SEARCH_PRIVMXSQLITEVFS_HPP_
#define _PRIVMXLIB_ENDPOINT_SEARCH_PRIVMXSQLITEVFS_HPP_

#include <sqlite3.h>

#define MAXPATHNAME 512

namespace privmx {
namespace endpoint {
namespace search {

extern "C" {

sqlite3_vfs* sqlite3_privmxvfs();

}


}  // namespace search
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_SEARCH_PRIVMXSQLITEVFS_HPP_
