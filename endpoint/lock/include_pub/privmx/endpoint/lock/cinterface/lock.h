/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMX_ENDPOINT_LOCK_INTERFACE_API_
#define _PRIVMX_ENDPOINT_LOCK_INTERFACE_API_

#include <Pson/pson.h>
#include <privmx/endpoint/core/cinterface/core.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct LockApi LockApi;

int privmx_endpoint_newLockApi(Connection* connectionPtr, LockApi** outPtr);
int privmx_endpoint_freeLockApi(LockApi* ptr);
int privmx_endpoint_execLockApi(LockApi* ptr, int method, const pson_value* args, pson_value** res);

#ifdef __cplusplus
}
#endif

#endif // _PRIVMX_ENDPOINT_LOCK_INTERFACE_API_
