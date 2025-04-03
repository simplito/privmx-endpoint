/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_THREAD_C_API_H_
#define _PRIVMXLIB_ENDPOINT_THREAD_C_API_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    privmx_ThreadApi_Create = 0,
    privmx_ThreadApi_CreateThread = 1,
    privmx_ThreadApi_UpdateThread = 2,
    privmx_ThreadApi_DeleteThread = 3,
    privmx_ThreadApi_GetThread = 4,
    privmx_ThreadApi_ListThreads = 5,
    privmx_ThreadApi_GetMessage = 6,
    privmx_ThreadApi_ListMessages = 7,
    privmx_ThreadApi_SendMessage = 8,
    privmx_ThreadApi_DeleteMessage = 9,
    privmx_ThreadApi_UpdateMessage = 10,
    privmx_ThreadApi_SubscribeForThreadEvents = 11,
    privmx_ThreadApi_UnsubscribeFromThreadEvents = 12,
    privmx_ThreadApi_SubscribeForMessageEvents = 13,
    privmx_ThreadApi_UnsubscribeFromMessageEvents = 14,
} privmx_ThreadApi_Method;

#ifdef __cplusplus
}
#endif

#endif // _PRIVMXLIB_ENDPOINT_THREAD_C_API_H_
