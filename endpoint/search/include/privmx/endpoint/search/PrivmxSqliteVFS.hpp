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

#include <exception>

#define MAXPATHNAME 512

namespace privmx {
namespace endpoint {
namespace search {

extern "C" {

sqlite3_vfs* sqlite3_privmxvfs();
}

/**
 * A VFS callback can only answer sqlite with `SQLITE_IOERR*`, which turns any underlying failure into a
 * misleading "disk I/O error". The original exception is stashed so the SearchApi boundary can rethrow it.
 */
void stashVfsException(std::exception_ptr error);

/** Rethrows and clears the exception stashed by the last failing VFS callback, if any. No-op otherwise. */
void rethrowStashedVfsException();

/**
 * Drops any stashed exception, on entering an operation: sqlite tolerates some VFS failures and returns
 * SQLITE_OK anyway, leaving a stale cause that the next, unrelated failure would rethrow.
 */
void clearStashedVfsException();

} // namespace search
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_SEARCH_PRIVMXSQLITEVFS_HPP_
