#ifndef _PRIVMX_ENDPOINT_CORE_INTERFACE_API_
#define _PRIVMX_ENDPOINT_CORE_INTERFACE_API_

#include <Pson/pson.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct EventQueue EventQueue;

int privmx_endpoint_newEventQueue(EventQueue** outPtr);
int privmx_endpoint_freeEventQueue(EventQueue* ptr);
int privmx_endpoint_execEventQueue(EventQueue* ptr, int method, const pson_value* args, pson_value** res);

typedef struct Connection Connection;
typedef int (*privmx_user_verifier)(void* ctx, const pson_value* args, pson_value** res);

int privmx_endpoint_newConnection(Connection** outPtr);
int privmx_endpoint_freeConnection(Connection* ptr);
int privmx_endpoint_setUserVerifier(Connection* ptr, void* ctx, privmx_user_verifier verifier, pson_value** res);
int privmx_endpoint_execConnection(Connection* ptr, int method, const pson_value* args, pson_value** res);

typedef struct BackendRequester BackendRequester;

int privmx_endpoint_newBackendRequester(BackendRequester** outPtr);
int privmx_endpoint_freeBackendRequester(BackendRequester* ptr);
int privmx_endpoint_execBackendRequester(BackendRequester* ptr, int method, const pson_value* args, pson_value** res);

typedef struct Utils Utils;

int privmx_endpoint_newUtils(Utils** outPtr);
int privmx_endpoint_freeUtils(Utils* ptr);
int privmx_endpoint_execUtils(Utils* ptr, int method, const pson_value* args, pson_value** res);

int privmx_endpoint_setCertsPath(const char* certsPath);

#ifdef __cplusplus
}
#endif

#endif // _PRIVMX_ENDPOINT_CORE_INTERFACE_API_
