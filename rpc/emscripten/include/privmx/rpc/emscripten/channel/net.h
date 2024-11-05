#ifndef __PRIVMX_DRIVER_NET_H__
#define __PRIVMX_DRIVER_NET_H__

#ifdef __cplusplus
extern "C" {
#endif

struct privmxDrvNet_HttpOptions
{
    const char* baseUrl;
    bool keepAlive;
};
typedef struct privmxDrvNet_HttpOptions privmxDrv_HttpOptions;

struct privmxDrvNet_HttpHeader
{
    const char* name;
    const char* value;
};
typedef struct privmxDrvNet_HttpHeader privmxDrvNet_HttpHeader;

struct privmxDrvNet_HttpRequestOptions
{
    const char* path;
    const char* method; // methods: GET, POST
    const char* contentType;
    const privmxDrvNet_HttpHeader* headers;
    int headerslen;
    bool keepAlive;
};
typedef struct privmxDrvNet_HttpRequestOptions privmxDrvNet_HttpRequestOptions;

struct privmxDrvNet_WsOptions
{
    const char* url;
}; 
typedef struct privmxDrvNet_WsOptions privmxDrvNet_WsOptions;

struct privmxDrvNet_Http;
typedef struct privmxDrvNet_Http privmxDrvNet_Http;
struct privmxDrvNet_Ws;
typedef struct privmxDrvNet_Ws privmxDrvNet_Ws;

int privmxDrvNet_version(unsigned int* version); // version: 1
int privmxDrvNet_setConfig(const char* config);
int privmxDrvNet_httpCreateSession(const privmxDrvNet_HttpOptions* options, privmxDrvNet_Http** res);
int privmxDrvNet_httpDestroySession(privmxDrvNet_Http* http);
int privmxDrvNet_httpFree(privmxDrvNet_Http* http);
int privmxDrvNet_httpRequest(privmxDrvNet_Http* http, const char* data, int datalen, const privmxDrvNet_HttpRequestOptions* options, int* statusCode, char** out, unsigned int* outlen);
int privmxDrvNet_wsConnect(const privmxDrvNet_WsOptions* options, void(*onopen)(void* ctx), void(*onmessage)(void* ctx, const char* msg, int msglen), void(*onerror)(void* ctx, const char* msg, int msglen), void(*onclose)(void* ctx, int wasClean), void* ctx, privmxDrvNet_Ws** res);
int privmxDrvNet_wsClose(privmxDrvNet_Ws* ws);
int privmxDrvNet_wsFree(privmxDrvNet_Ws* ws);
int privmxDrvNet_wsSend(privmxDrvNet_Ws* ws, const char* data, int datalen);
int privmxDrvNet_freeMem(void* ptr);

#ifdef __cplusplus
}
#endif

#endif // __PRIVMX_DRIVER_NET_H__
