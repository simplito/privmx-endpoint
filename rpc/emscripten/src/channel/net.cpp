/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <cstdlib>
#include <iterator>
#include <string>
#include <unordered_map>
#include <emscripten/emscripten.h>
#include <emscripten/eventloop.h>
#include <emscripten/bind.h>
#include <emscripten/proxying.h>
#include <privmx/drv/net.h>
#include <chrono>
#include <map>
#include <iostream>
#include <memory>
#include <thread>
#include "privmx/rpc/emscripten/channel/websocket.h"

struct privmxDrvNet_Http {
    std::string uri;
};

struct privmxDrvNet_Ws {
    int websocketId;
};

emscripten::ProxyingQueue _queue;

std::thread wsWorker = std::thread([]{
    emscripten_runtime_keepalive_push();
});

void runTaskAsync(const std::function<void(void)>& func){
    _queue.proxyAsync(wsWorker.native_handle(),[&,func]{
        func();
    });
}

void runTaskSync(const std::function<void(void)>& func){
    _queue.proxySync(wsWorker.native_handle(),[&,func]{
        func();
    });
}

EM_JS(emscripten::EM_VAL,getOrigin, (const char* url),{
    const new_url = new URL(UTF8ToString(url));
    const uri = new_url.origin;
    return Emval.toHandle(uri);
});

EM_ASYNC_JS(emscripten::EM_VAL, callJSFetch, (emscripten::EM_VAL val_handle), {
    let params = Emval.toValue(val_handle);
    let result = {status: -1, data: "", error: ""};
    try {
        let response = await fetch(params.url, params);
        let status = await response.status;
        let data = await response.arrayBuffer();
        result = {status, data, error: ""};
    } catch (error) {
        result = {status: -1, data: "", error: error.toString()};
    }
    return Emval.toHandle(result);
});

std::tuple<int,std::string> HTTPSend(const std::string& data, const std::string& url, const std::string& content_type, bool get, const std::map<std::string,std::string>& request_headers, bool keepAlive) {
    int status;
    std::string response_data;
    try {
        emscripten::val params = emscripten::val::object();
        emscripten::val headers = emscripten::val::object();
        params.set("url", url);
        params.set("method", get ? "GET" : "POST");
        if (!get) {
            params.set("body", emscripten::val::global("Uint8Array").new_(emscripten::typed_memory_view(data.size(), data.data())));
            headers.set("Content-Type", content_type);
            for (auto& [key, value]: request_headers){
                headers.set(key,value);
            }
        }
        params.set("headers", headers);
        emscripten::val response = emscripten::val::take_ownership(callJSFetch(params.as_handle()));
        status = response["status"].as<int>();
        response_data = response["data"].as<std::string>();
    } catch (...) {
    }
    emscripten_sleep(0);
    return {status,response_data};
}
 
int privmxDrvNet_version(unsigned int* version) {
    *version = 1;
    return 0;
}

int privmxDrvNet_setConfig(const char* config) {
    return 0;
}

int privmxDrvNet_httpCreateSession(const privmxDrvNet_HttpOptions* options, privmxDrvNet_Http** res) {
    try {
        std::string cpp_str_url(options->baseUrl);
        cpp_str_url = emscripten::val::take_ownership(getOrigin(cpp_str_url.c_str())).as<std::string>();
        *res = new privmxDrvNet_Http{cpp_str_url};
        return 0;
    } catch(...) {
        return 1;
    }
}

int privmxDrvNet_httpDestroySession(privmxDrvNet_Http* http) {
    return 0;
}

int privmxDrvNet_httpFree(privmxDrvNet_Http* http) {
    delete http;
    return 0;
}

int privmxDrvNet_httpRequest(privmxDrvNet_Http* http, const char* data, int datalen, const privmxDrvNet_HttpRequestOptions* options, int* statusCode, char** out, unsigned int* outlen) {
    try {
        std::string cpp_str_data(data, datalen);
        std::string path(options->path);
        path = http->uri+path;
        std::string contentType(options->contentType);
        std::string method(options->method);
        std::map<std::string,std::string> headers;
        for (int i = 0; i < options->headerslen; ++i) {
            headers.emplace(std::make_pair(std::string(options->headers[i].name), std::string(options->headers[i].value)));
        } 
        auto response = HTTPSend(cpp_str_data,path,contentType,(method=="GET") ? true : false,headers,options->keepAlive);
        int response_status = std::get<0>(response);
        std::string response_data = std::get<1>(response);
        char* buf = reinterpret_cast<char*>(malloc(response_data.size()));
        memcpy(buf, response_data.data(), response_data.size());
        *statusCode = response_status;
        *out = buf;
        *outlen = response_data.size();
        return 0;
    } catch (...) {
        return 1;
    }
}

int privmxDrvNet_wsConnect(const privmxDrvNet_WsOptions* options, 
                           void(*onopen)(void* ctx), 
                           void(*onmessage)(void* ctx, const char* msg, int msglen), 
                           void(*onerror)(void* ctx, const char* msg, int msglen), 
                           void(*onclose)(void* ctx, int wasClean), void* ctx,
                           privmxDrvNet_Ws** res){

    std::string cpp_str_uri("ws");
    cpp_str_uri.append(std::string(options->url).substr(4));
    int websocketId;

    runTaskSync([&]{
        try {
            websocketId = wsCreateWebSocket(cpp_str_uri.c_str());
            wsSetUserPointer(websocketId,ctx);
            wsSetOpenCallback(websocketId, onopen);
            wsSetErrorCallback(websocketId, onerror);
            wsSetMessageCallback(websocketId, onmessage);
            wsSetCloseCallback(websocketId, onclose);
        } 
        catch(...) {}
    });
    *res = new privmxDrvNet_Ws{.websocketId=websocketId};
    return 0;

}

int privmxDrvNet_wsClose(privmxDrvNet_Ws* ws) {
    runTaskSync([&]{
        try {
            wsDeleteWebSocket(ws->websocketId);
        } catch(...) {}
    });
    return 0;
}

int privmxDrvNet_wsFree(privmxDrvNet_Ws* ws) {
    delete ws;
    return 0;
}

int privmxDrvNet_wsSend(privmxDrvNet_Ws* ws, const char* data, int datalen) {
    int result = -1;
    runTaskSync([&]{
        try {
            result = wsSendMessage(ws->websocketId,data,datalen);
        } catch(...) {}
    });
    if(result <= 0){
        return 1;
    } 
    return 0;
}

int privmxDrvNet_freeMem(void* ptr) {
    free(ptr);
    return 0;
}
