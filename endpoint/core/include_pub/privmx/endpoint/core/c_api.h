/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_CORE_C_API_H_
#define _PRIVMXLIB_ENDPOINT_CORE_C_API_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    privmx_BackendRequester_BackendRequest = 0,
} privmx_BackendRequester_Method;

typedef enum {
    privmx_Connection_Connect = 0,
    privmx_Connection_ConnectPublic = 1,
    privmx_Connection_GetConnectionId = 2,
    privmx_Connection_ListContexts = 3,
    privmx_Connection_Disconnect = 4,
    privmx_Connection_GetContextUsers = 5,
} privmx_Connection_Method;

typedef enum {
    privmx_EventQueue_WaitEvent = 0,
    privmx_EventQueue_GetEvent = 1,
    privmx_EventQueue_EmitBreakEvent = 2,
} privmx_EventQueue_Method;

#ifdef __cplusplus
}
#endif

#endif // _PRIVMXLIB_ENDPOINT_CORE_C_API_H_
