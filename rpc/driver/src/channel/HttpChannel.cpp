#include <exception>
#include <privmx/drv/net.h>

#include <privmx/rpc/driver/channel/HttpChannel.hpp>
#include <privmx/rpc/RpcException.hpp>
#include <privmx/crypto/OpenSSLUtils.hpp>

using namespace privmx;
using namespace privmx::rpc::driverimpl;
using namespace privmx::utils;
using namespace std;
using namespace Poco;

HttpChannel::HttpChannel(const URI& uri, bool keepAlive) : rpc::HttpChannel(uri), _keepAlive(keepAlive) {}

HttpChannel::~HttpChannel() {
    if (_http) {
        privmxDrvNet_httpFree(_http);
    }
}

future<string> HttpChannel::send(const string& data, const string& path, const std::vector<std::pair<std::string, std::string>>& headers, [[maybe_unused]] privmx::utils::CancellationToken::Ptr token, const string& content_type, bool get, bool keepAlive) {
    Lock lock(_mutex);
    if (_http == nullptr) {
        Poco::URI url2 = _uri;
        url2.setPath(path);
        string url = url2.toString();
        privmxDrvNet_HttpOptions options;
        options.baseUrl = url.c_str();
        options.keepAlive = _keepAlive;
        int status = privmxDrvNet_httpCreateSession(&options, &_http);
        if (status != 0) {
            throw HttpConnectException(to_string(status));
        }
    }
    int statusCode;
    char* out;
    unsigned int outlen;
    privmxDrvNet_HttpRequestOptions options;
    options.contentType = content_type.c_str();
    options.method = get ? "GET" : "POST";
    options.path = path.c_str();
    std::vector<privmxDrvNet_HttpHeader > tmp;
    for (unsigned long i = 0; i < headers.size(); ++i) {
        tmp[i].name = headers[i].first.c_str();
        tmp[i].value = headers[i].second.c_str();
    }
    options.headers = tmp.data();
    options.headerslen = headers.size();
    options.keepAlive = keepAlive;
    int status = privmxDrvNet_httpRequest(_http, data.data(), data.size(), &options, &statusCode, &out, &outlen);
    if (status != 0 || statusCode != 200) {
        throw HttpRequestException(to_string(status) + " " + to_string(statusCode));
    }
    string result(out, outlen);
    privmxDrvNet_freeMem(out);
    promise<string> promise;
    promise.set_value(result);
    return promise.get_future();
}
