#ifndef _PRIVMX_ENDPOINT_THREAD_INTERFACE_API_
#define _PRIVMX_ENDPOINT_THREAD_INTERFACE_API_

#include <Pson/pson.h>
#include <privmx/endpoint/core/cinterface/core.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ThreadApi ThreadApi;

int privmx_endpoint_newThreadApi(Connection* connectionPtr, ThreadApi** outPtr);
int privmx_endpoint_freeThreadApi(ThreadApi* ptr);
int privmx_endpoint_execThreadApi(ThreadApi* ptr, int method, const pson_value* args, pson_value** res);

#ifdef __cplusplus
}
#endif

#endif // _PRIVMX_ENDPOINT_THREAD_INTERFACE_API_
