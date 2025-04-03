/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_INBOX_C_API_H_
#define _PRIVMXLIB_ENDPOINT_INBOX_C_API_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    privmx_InboxApi_Create = 0,
    privmx_InboxApi_CreateInbox = 1,
    privmx_InboxApi_UpdateInbox = 2,
    privmx_InboxApi_GetInbox = 3,
    privmx_InboxApi_ListInboxes = 4,
    privmx_InboxApi_GetInboxPublicView = 5,
    privmx_InboxApi_DeleteInbox = 6,
    privmx_InboxApi_PrepareEntry = 7,
    privmx_InboxApi_SendEntry = 8,
    privmx_InboxApi_ReadEntry = 9,
    privmx_InboxApi_ListEntries = 10,
    privmx_InboxApi_DeleteEntry = 11,
    privmx_InboxApi_CreateFileHandle = 12,
    privmx_InboxApi_WriteToFile = 13,
    privmx_InboxApi_OpenFile = 14,
    privmx_InboxApi_ReadFromFile = 15,
    privmx_InboxApi_SeekInFile = 16,
    privmx_InboxApi_CloseFile = 17,
    privmx_InboxApi_SubscribeForInboxEvents = 18,
    privmx_InboxApi_UnsubscribeFromInboxEvents = 19,
    privmx_InboxApi_SubscribeForEntryEvents = 20,
    privmx_InboxApi_UnsubscribeFromEntryEvents = 21,
} privmx_InboxApi_Method;

#ifdef __cplusplus
}
#endif

#endif // _PRIVMXLIB_ENDPOINT_INBOX_C_API_H_
