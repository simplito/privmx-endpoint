/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_EVENT_C_API_H_
#define _PRIVMXLIB_ENDPOINT_EVENT_C_API_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    privmx_EventApi_Create = 0,
    privmx_EventApi_EmitEvent = 1,
    privmx_EventApi_SubscribeForCustomEvents = 2,
    privmx_EventApi_UnsubscribeFromCustomEvents = 3,
} privmx_EventApi_Method;

#ifdef __cplusplus
}
#endif

#endif // _PRIVMXLIB_ENDPOINT_EVENT_C_API_H_
