#ifndef _PRIVMX_ENDPOINT_EVENT_INTERFACE_API_
#define _PRIVMX_ENDPOINT_EVENT_INTERFACE_API_

#include <Pson/pson.h>
#include <privmx/endpoint/core/cinterface/core.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct EventApi EventApi;

int privmx_endpoint_newEventApi(Connection* connectionPtr, EventApi** outPtr);
int privmx_endpoint_freeEventApi(EventApi* ptr);
int privmx_endpoint_execEventApi(EventApi* ptr, int method, const pson_value* args, pson_value** res);

#ifdef __cplusplus
}
#endif

#endif // _PRIVMX_ENDPOINT_EVENT_INTERFACE_API_
