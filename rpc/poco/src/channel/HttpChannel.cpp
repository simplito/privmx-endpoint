/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <exception>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/Net/NetException.h>

#include <privmx/rpc/poco/channel/HttpChannel.hpp>
#include <privmx/rpc/poco/utils/HTTPClientSessionFactory.hpp>
#include <privmx/utils/PrivmxExtExceptions.hpp>
#include <privmx/utils/Utils.hpp>

using namespace privmx;
using namespace privmx::rpc::pocoimpl;
using namespace privmx::utils;
using namespace std;
using namespace Poco;
using namespace Poco::Net;

HttpChannel::HttpChannel(const URI& uri, const bool keepAlive) : rpc::HttpChannel(uri) {
    _http_client = HTTPClientSessionFactory::create(uri);
    _http_client->setKeepAliveTimeout(Timespan(30, 0));
    _http_client->setKeepAlive(keepAlive);
}

future<string> HttpChannel::send(const string& data, const string& path, const std::vector<std::pair<std::string, std::string>>& headers, privmx::utils::CancellationToken::Ptr token, const string& content_type, bool get, bool keepAlive) {
    HTTPRequest request(get ? HTTPRequest::HTTP_GET : HTTPRequest::HTTP_POST, path);
    
    request.setKeepAlive(keepAlive);
    request.setContentLength(data.length());
    request.setContentType(content_type);
    for (auto& header: headers) {
        request.set(header.first, header.second);
    }
    promise<string> promise;
    string result;
    try {
        Lock lock(_mutex);
        CancellationToken::Task cancel_task(token, [&]{ _http_client->abort(); });
        ostream& out = _http_client->sendRequest(request);
        out << data << flush;
        HTTPResponse response;
        istream& stream = _http_client->receiveResponse(response);
        if (response.getStatus() != HTTPResponse::HTTP_OK) {
            _http_client->reset();
            throw InvalidHttpStatusException();
        }
        updateKeepAlive(response);
        result = string{istreambuf_iterator<char>(stream), istreambuf_iterator<char>()};
        promise.set_value(result);
    } catch (const Poco::Net::NoMessageException& e) {
        promise.set_exception(make_exception_ptr(NoMessageReceivedException()));
    } catch (const NetException& e) {
        promise.set_exception(make_exception_ptr(NetConnectionException(e.what())));
    } catch (const TimeoutException& e) {
        promise.set_exception(make_exception_ptr(NetConnectionException(e.what())));
    } catch (const InvalidHttpStatusException& e) {
        promise.set_exception(make_exception_ptr(e));
    } catch (...) {
        promise.set_exception(make_exception_ptr(current_exception()));
    }
    return promise.get_future();
}

#include <iostream>
void HttpChannel::updateKeepAlive(const HTTPResponse& response) {
    std::string keepAliveRaw = response.get("Keep-Alive");
    std::vector<std::string> keepAliveValues = Utils::split(keepAliveRaw, ",");
    for(auto v: keepAliveValues) {
        std::vector<std::string> tmp = Utils::split(Utils::trim(v), "=");
        if(tmp.size() != 2) continue;
        if(tmp[0] == "timeout") {
            _http_client->setKeepAliveTimeout(Timespan(std::stoi(tmp[1]), 0));
        }
    }
}
