#ifndef _PRIVMX_ENDPOINT_INTERFACE_ENDPOINT_API_
#define _PRIVMX_ENDPOINT_INTERFACE_ENDPOINT_API_

#include <Pson/pson.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct EventQueue EventQueue;

int privmx_endpoint_newEventQueue(EventQueue** outPtr);
int privmx_endpoint_freeEventQueue(EventQueue* ptr);
int privmx_endpoint_execEventQueue(EventQueue* ptr, int method, const pson_value* args, pson_value** res);

typedef struct Connection Connection;
typedef int (*privmx_user_verifier)(const pson_value* args, pson_value** res);

int privmx_endpoint_newConnection(Connection** outPtr);
int privmx_endpoint_freeConnection(Connection* ptr);
int privmx_endpoint_setUserVerifier(Connection* ptr, privmx_user_verifier verifier, pson_value** res);
int privmx_endpoint_execConnection(Connection* ptr, int method, const pson_value* args, pson_value** res);

typedef struct BackendRequester BackendRequester;

int privmx_endpoint_newBackendRequester(BackendRequester** outPtr);
int privmx_endpoint_freeBackendRequester(BackendRequester* ptr);
int privmx_endpoint_execBackendRequester(BackendRequester* ptr, int method, const pson_value* args, pson_value** res);

typedef struct ThreadApi ThreadApi;

int privmx_endpoint_newThreadApi(Connection* connectionPtr, ThreadApi** outPtr);
int privmx_endpoint_freeThreadApi(ThreadApi* ptr);
int privmx_endpoint_execThreadApi(ThreadApi* ptr, int method, const pson_value* args, pson_value** res);

typedef struct StoreApi StoreApi;

int privmx_endpoint_newStoreApi(Connection* connectionPtr, StoreApi** outPtr);
int privmx_endpoint_freeStoreApi(StoreApi* ptr);
int privmx_endpoint_execStoreApi(StoreApi* ptr, int method, const pson_value* args, pson_value** res);

typedef struct InboxApi InboxApi;

int privmx_endpoint_newInboxApi(Connection* connectionPtr, ThreadApi* threadApi, StoreApi* storeApi, InboxApi** outPtr);
int privmx_endpoint_freeInboxApi(InboxApi* ptr);
int privmx_endpoint_execInboxApi(InboxApi* ptr, int method, const pson_value* args, pson_value** res);

typedef struct KvdbApi KvdbApi;

int privmx_endpoint_newKvdbApi(Connection* connectionPtr, KvdbApi** outPtr);
int privmx_endpoint_freeKvdbApi(KvdbApi* ptr);
int privmx_endpoint_execKvdbApi(KvdbApi* ptr, int method, const pson_value* args, pson_value** res);

typedef struct CryptoApi CryptoApi;

int privmx_endpoint_newCryptoApi(CryptoApi** outPtr);
int privmx_endpoint_freeCryptoApi(CryptoApi* ptr);
int privmx_endpoint_execCryptoApi(CryptoApi* ptr, int method, const pson_value* args, pson_value** res);

typedef struct ExtKey ExtKey;

int privmx_endpoint_newExtKey(ExtKey** outPtr);
int privmx_endpoint_freeExtKey(ExtKey* ptr);
int privmx_endpoint_execExtKey(ExtKey* ptr, int method, const pson_value* args, pson_value** res);

typedef struct EventApi EventApi;

int privmx_endpoint_newEventApi(Connection* connectionPtr, EventApi** outPtr);
int privmx_endpoint_freeEventApi(EventApi* ptr);
int privmx_endpoint_execEventApi(EventApi* ptr, int method, const pson_value* args, pson_value** res);

typedef struct Utils Utils;

int privmx_endpoint_newUtils(Utils** outPtr);
int privmx_endpoint_freeUtils(Utils* ptr);
int privmx_endpoint_execUtils(Utils* ptr, int method, const pson_value* args, pson_value** res);

int privmx_endpoint_setCertsPath(const char* certsPath);

#ifdef __cplusplus
}
#endif

#endif // _PRIVMX_ENDPOINT_INTERFACE_ENDPOINT_API_
