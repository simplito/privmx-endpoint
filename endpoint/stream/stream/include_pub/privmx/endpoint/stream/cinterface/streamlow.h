#ifndef _PRIVMX_ENDPOINT_STREAM_LOW_INTERFACE_API_
#define _PRIVMX_ENDPOINT_STREAM_LOW_INTERFACE_API_

#include <Pson/pson.h>
#include "privmx/endpoint/core/cinterface/core.h"
#include "privmx/endpoint/event/cinterface/event.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct StreamApiLow StreamApiLow;

int privmx_endpoint_newStreamApiLow(Connection* connectionPtr, EventApi* eventApi, StreamApiLow** outPtr);
int privmx_endpoint_freeStreamApiLow(StreamApiLow* ptr);
int privmx_endpoint_execStreamApiLow(StreamApiLow* ptr, int method, const pson_value* args, pson_value** res);

enum privmx_endpoint_stream_KeyType
{
    privmx_endpoint_stream_KeyType_LOCAL,
    privmx_endpoint_stream_KeyType_REMOTE
};

struct privmx_endpoint_stream_Key
{
    const char* keyId;
    const unsigned char* key;
    size_t keySize;
    privmx_endpoint_stream_KeyType type;
};
typedef struct privmx_endpoint_stream_Key privmx_endpoint_stream_Key;

typedef const char* (*CreateOfferAndSetLocalDescriptionCallback)(void* ctx, const char* streamRoomId);
typedef const char* (*CreateAnswerAndSetDescriptionsCallback)(void* ctx, const char* streamRoomId, const char* sdp, const char* type);
typedef void (*SetAnswerAndSetRemoteDescriptionCallback)(void* ctx, const char* streamRoomId, const char* sdp, const char* type);
typedef void (*UpdateSessionIdCallback)(void* ctx, const char* streamRoomId, const int64_t sessionId, const char* connectionType);
typedef void (*CloseCallback)(void* ctx, const char* streamRoomId);
typedef void (*UpdateKeysCallback)(void* ctx, const char* streamRoomId, const privmx_endpoint_stream_Key keys[], const size_t keysSize);

typedef struct privmx_endpoint_stream_ProxyWebRTC privmx_endpoint_stream_ProxyWebRTC;

int privmx_endpoint_stream_newProxyWebRTC(
    void* ctx,
    CreateOfferAndSetLocalDescriptionCallback callback1,
    CreateAnswerAndSetDescriptionsCallback  callback2,
    SetAnswerAndSetRemoteDescriptionCallback callback3,
    UpdateSessionIdCallback callback4,
    CloseCallback callback5,
    UpdateKeysCallback callback6,
    privmx_endpoint_stream_ProxyWebRTC** outPtr
);

int privmx_endpoint_stream_freeProxyWebRTC(privmx_endpoint_stream_ProxyWebRTC* ptr);

#ifdef __cplusplus
}
#endif

#endif // _PRIVMX_ENDPOINT_INBOX_INTERFACE_API_
