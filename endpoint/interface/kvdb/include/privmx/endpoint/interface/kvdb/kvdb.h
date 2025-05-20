#ifndef _PRIVMX_ENDPOINT_KVDB_INTERFACE_API_
#define _PRIVMX_ENDPOINT_KVDB_INTERFACE_API_

#include <Pson/pson.h>
#include "privmx/endpoint/interface/core/core.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct KvdbApi KvdbApi;

int privmx_endpoint_newKvdbApi(Connection* connectionPtr, KvdbApi** outPtr);
int privmx_endpoint_freeKvdbApi(KvdbApi* ptr);
int privmx_endpoint_execKvdbApi(KvdbApi* ptr, int method, const pson_value* args, pson_value** res);

#ifdef __cplusplus
}
#endif

#endif // _PRIVMX_ENDPOINT_KVDB_INTERFACE_API_
