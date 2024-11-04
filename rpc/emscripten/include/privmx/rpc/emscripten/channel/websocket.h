#ifndef __PRIVMXLIB_RPC_EMSCRIPTEN_WEBSOCKET_H___
#define __PRIVMXLIB_RPC_EMSCRIPTEN_WEBSOCKET_H___

#include <emscripten/emscripten.h>

#include <exception>
#include <memory>

#ifdef __cplusplus
extern "C" {
#endif

    extern int wsCreateWebSocket(const char *url);
    extern void wsDeleteWebSocket(int ws);
    extern void wsSetOpenCallback(int ws, void (*onopen)(void *));
    extern void wsSetCloseCallback(int ws, void (*onclose)(void *, int));
    extern void wsSetErrorCallback(int ws, void (*onerror)(void*, const char*, int));
    extern void wsSetMessageCallback(int ws, void (*onmessage)(void*, const char*, int ));
    extern int wsSendMessage(int ws, const char *buffer, int size);
    extern void wsSetUserPointer(int ws, void *ptr);
    
#ifdef __cplusplus
}
#endif

#endif // __PRIVMXLIB_RPC_EMSCRIPTEN_WEBSOCKET_H___
