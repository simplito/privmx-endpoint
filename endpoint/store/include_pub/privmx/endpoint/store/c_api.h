/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_STORE_C_API_H_
#define _PRIVMXLIB_ENDPOINT_STORE_C_API_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    privmx_StoreApi_Create = 0,
    privmx_StoreApi_CreateStore = 1,
    privmx_StoreApi_UpdateStore = 2,
    privmx_StoreApi_DeleteStore = 3,
    privmx_StoreApi_GetStore = 4,
    privmx_StoreApi_ListStores = 5,
    privmx_StoreApi_CreateFile = 6,
    privmx_StoreApi_UpdateFile = 7,
    privmx_StoreApi_UpdateFileMeta = 8,
    privmx_StoreApi_WriteToFile = 9,
    privmx_StoreApi_DeleteFile = 10,
    privmx_StoreApi_GetFile = 11,
    privmx_StoreApi_ListFiles = 12,
    privmx_StoreApi_OpenFile = 13,
    privmx_StoreApi_ReadFromFile = 14,
    privmx_StoreApi_SeekInFile = 15,
    privmx_StoreApi_CloseFile = 16,
    privmx_StoreApi_SubscribeForStoreEvents = 17,
    privmx_StoreApi_UnsubscribeFromStoreEvents = 18,
    privmx_StoreApi_SubscribeForFileEvents = 19,
    privmx_StoreApi_UnsubscribeFromFileEvents = 20,
} privmx_StoreApi_Method;

#ifdef __cplusplus
}
#endif

#endif // _PRIVMXLIB_ENDPOINT_STORE_C_API_H_
