#ifndef _PRIVMX_ENDPOINT_STORE_INTERFACE_API_
#define _PRIVMX_ENDPOINT_STORE_INTERFACE_API_

#include <Pson/pson.h>
#include <privmx/endpoint/core/cinterface/core.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct StoreApi StoreApi;

int privmx_endpoint_newStoreApi(Connection* connectionPtr, StoreApi** outPtr);
int privmx_endpoint_freeStoreApi(StoreApi* ptr);
int privmx_endpoint_execStoreApi(StoreApi* ptr, int method, const pson_value* args, pson_value** res);

#ifdef __cplusplus
}
#endif

#endif // _PRIVMX_ENDPOINT_STORE_INTERFACE_API_
