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

int privmx_endpoint_newConnection(Connection** outPtr);
int privmx_endpoint_freeConnection(Connection* ptr);
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

typedef struct CryptoApi CryptoApi;

int privmx_endpoint_newCryptoApi(CryptoApi** outPtr);
int privmx_endpoint_freeCryptoApi(CryptoApi* ptr);
int privmx_endpoint_execCryptoApi(CryptoApi* ptr, int method, const pson_value* args, pson_value** res);

int privmx_endpoint_setCertsPath(const char* certsPath);

#ifdef __cplusplus
}
#endif

#endif // _PRIVMX_ENDPOINT_INTERFACE_ENDPOINT_API_
