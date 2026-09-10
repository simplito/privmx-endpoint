/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMX_ENDPOINT_SEARCH_INTERFACE_API_
#define _PRIVMX_ENDPOINT_SEARCH_INTERFACE_API_

#include <Pson/pson.h>
#include <privmx/endpoint/core/cinterface/core.h>
#include <privmx/endpoint/kvdb/cinterface/kvdb.h>
#include <privmx/endpoint/lock/cinterface/lock.h>
#include <privmx/endpoint/store/cinterface/store.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SearchApi SearchApi;

int privmx_endpoint_newSearchApi(
    Connection* connectionPtr,
    StoreApi* storeApiPtr,
    KvdbApi* kvdbApiPtr,
    LockApi* lockApiPtr,
    SearchApi** outPtr
);
int privmx_endpoint_freeSearchApi(SearchApi* ptr);
int privmx_endpoint_execSearchApi(SearchApi* ptr, int method, const pson_value* args, pson_value** res);

#ifdef __cplusplus
}
#endif

#endif // _PRIVMX_ENDPOINT_SEARCH_INTERFACE_API_
