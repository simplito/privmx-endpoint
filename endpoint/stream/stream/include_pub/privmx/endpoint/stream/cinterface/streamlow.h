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

#ifdef __cplusplus
}
#endif

#endif // _PRIVMX_ENDPOINT_INBOX_INTERFACE_API_
