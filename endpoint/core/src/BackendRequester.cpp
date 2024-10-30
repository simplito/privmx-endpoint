#include <Poco/URI.h>
#include <Poco/JSON/Parser.h>

#include <privmx/rpc/channel/ChannelEnv.hpp>
#include <privmx/utils/Utils.hpp>

#include "privmx/endpoint/core/BackendRequester.hpp"
#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/ECC.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <regex>
#include <optional>

using namespace privmx::endpoint::core;

/**
 * using acccess token
 */
std::string BackendRequester::backendRequest(
    const std::string& serverUrl, 
    const std::string& accessToken, 
    const std::string& method, 
    const std::string& paramsAsJson
) {
    std::vector<std::pair<std::string, std::string>> headers {};
    std::string authorization {"Bearer " + accessToken};
    headers.push_back(std::pair<std::string, std::string>("Authorization", authorization));
    return _backendRequest(serverUrl, headers, method, paramsAsJson);
}


/** public */
std::string BackendRequester::backendRequest(
    const std::string& serverUrl, 
    const std::string& method, 
    const std::string& paramsAsJson
) {
    std::vector<std::pair<std::string, std::string>> headers {};
    return _backendRequest(serverUrl, headers, method, paramsAsJson);
}

std::string BackendRequester::backendRequest(
    const std::string& serverUrl, 
    const std::string& apiKeyId, 
    const std::string& apiKeySecret, 
    const int64_t mode,
    const std::string& method,
    const std::string& paramsAsJson
) {
    if (mode == 0) {
        std::vector<std::pair<std::string, std::string>> headers {};
        std::string authorization {"Basic " + privmx::utils::Base64::from(apiKeyId + ":" + apiKeySecret)};
        headers.push_back(std::pair<std::string, std::string>("Authorization", authorization));
        return _backendRequest(serverUrl, headers, method, paramsAsJson);
    }
    else if(mode == 1) {
        Poco::URI uri {serverUrl.c_str()};
        std::string contentType {"application/json"};
        auto httpChannel {privmx::rpc::ChannelEnv::getHttpChannel(uri, false)};
        
        Poco::JSON::Object::Ptr request_json = new Poco::JSON::Object();
        Poco::JSON::Parser parser;
        Poco::Dynamic::Var result = parser.parse(paramsAsJson);
        Poco::JSON::Object::Ptr paramsObject = result.extract<Poco::JSON::Object::Ptr>();
        
        request_json->set("jsonrpc", "2.0");
        request_json->set("id", 0);
        request_json->set("method", method);
        request_json->set("params", paramsObject);

        // preparing data to be signed
        std::string requestPayload {utils::Utils::stringify(request_json)};
        std::string requestData {"POST\n/api\n" +requestPayload+ "\n"}; // UPPERCASE(HTTP_METHOD()) + "\n" + URI() + "\n" + RequestBody + "\n";
        auto timestamp = utils::Utils::getNowTimestampStr();
        std::string nonce {utils::Base64::from(crypto::Crypto::randomBytes(16))};
        std::string dataToSign {timestamp + ";" + nonce + ";" + requestData};  //= `${timestamp};${nonce};${requestData}`;

        auto signature = utils::Base64::from(crypto::Crypto::hmacSha256(apiKeySecret, dataToSign).substr(0, 20));

        std::vector<std::pair<std::string, std::string>> headers {};
        std::string authorization {"pmx-hmac-sha256 " + apiKeyId + ";1;" + timestamp + ";" + nonce + ";" + signature};
        headers.push_back(std::pair<std::string, std::string>("Authorization", authorization));

        auto requestString {utils::Utils::stringify(request_json)};
        return httpChannel->send(requestString, "/api", headers, privmx::utils::CancellationToken::create(), contentType, false, false).get();
    }
    else {
        throw new core::InvalidBackendRequestModeException();
    }
}

std::string BackendRequester::_backendRequest(
    const std::string& serverUrl,
    const std::vector<std::pair<std::string, std::string>> headers, 
    const std::string& method, 
    const std::string& paramsAsJson
) {
    Poco::URI uri {serverUrl.c_str()};
    std::string contentType {"application/json"};
    auto httpChannel {privmx::rpc::ChannelEnv::getHttpChannel(uri, false)};
    
    Poco::JSON::Object::Ptr request_json = new Poco::JSON::Object();
    Poco::JSON::Parser parser;
    Poco::Dynamic::Var result = parser.parse(paramsAsJson);
    Poco::JSON::Object::Ptr paramsObject = result.extract<Poco::JSON::Object::Ptr>();
    request_json->set("jsonrpc", "2.0");
    request_json->set("id", 0);
    request_json->set("method", method);
    request_json->set("params", paramsObject);
    auto requestString {utils::Utils::stringify(request_json)};
    return httpChannel->send(requestString, "/api", headers, privmx::utils::CancellationToken::create(), contentType, false, false).get();
}
