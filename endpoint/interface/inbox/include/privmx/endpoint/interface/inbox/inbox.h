#ifndef _PRIVMX_ENDPOINT_INBOX_INTERFACE_API_
#define _PRIVMX_ENDPOINT_INBOX_INTERFACE_API_

#include <Pson/pson.h>
#include "privmx/endpoint/interface/core/core.h"
#include "privmx/endpoint/interface/thread/thread.h"
#include "privmx/endpoint/interface/store/store.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct InboxApi InboxApi;

int privmx_endpoint_newInboxApi(Connection* connectionPtr, ThreadApi* threadApi, StoreApi* storeApi, InboxApi** outPtr);
int privmx_endpoint_freeInboxApi(InboxApi* ptr);
int privmx_endpoint_execInboxApi(InboxApi* ptr, int method, const pson_value* args, pson_value** res);

#ifdef __cplusplus
}
#endif

#endif // _PRIVMX_ENDPOINT_INBOX_INTERFACE_API_
