#ifndef _PRIVMX_ENDPOINT_GROUP_INTERFACE_API_
#define _PRIVMX_ENDPOINT_GROUP_INTERFACE_API_

#include <Pson/pson.h>
#include <privmx/endpoint/core/cinterface/core.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct GroupApi GroupApi;

int privmx_endpoint_newGroupApi(Connection* connectionPtr, GroupApi** outPtr);
int privmx_endpoint_freeGroupApi(GroupApi* ptr);
int privmx_endpoint_execGroupApi(GroupApi* ptr, int method, const pson_value* args, pson_value** res);

#ifdef __cplusplus
}
#endif

#endif // _PRIVMX_ENDPOINT_GROUP_INTERFACE_API_
