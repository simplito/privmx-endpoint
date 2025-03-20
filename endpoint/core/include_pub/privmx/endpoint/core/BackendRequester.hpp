#ifndef _PRIVMXLIB_ENDPOINT_CORE_BACKENDREQUESTER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_BACKENDREQUESTER_HPP_

#include <string>
#include <optional>
#include <vector>

namespace privmx {
namespace endpoint {
namespace core {

/**
 * 'BackendRequester' provides functions to call PrivMX Bridge API.
 */
class BackendRequester {
public:

    /**
     * Sends a request to PrivMX Bridge API using access token for authorization.
     * 
     * @param serverUrl PrivMX Bridge server URL
     * @param accessToken token for authorization (see PrivMX Bridge API for more details)
     * @param method API method to call
     * @param paramsAsJson API method's parameters in JSON format
     * 
     * @return JSON string representing raw server response
     */
    static std::string backendRequest(
        const std::string& serverUrl, 
        const std::string& accessToken,
        const std::string& method,
        const std::string& paramsAsJson
    );
    
    
    /**
     * Sends request to PrivMX Bridge API.
     * 
     * @param serverUrl PrivMX Bridge server URL
     * @param method API method to call
     * @param paramsAsJson API method's parameters in JSON format
     * 
     * @return JSON string representing raw server response
     */
    static std::string backendRequest(
        const std::string& serverUrl,
        const std::string& method, 
        const std::string& paramsAsJson
    );
    
    /**
     * Sends a request to PrivMX Bridge API using pair of API KEY ID and API KEY SECRET for authorization.
     * 
     * @param serverUrl PrivMX Bridge server URL
     * @param apiKeyId API KEY ID (see PrivMX Bridge API for more details)
     * @param apiKeySecret API KEY SECRET (see PrivMX Bridge API for more details)
     * @param mode allows you to set whether the request should be signed (mode = 1) or plain (mode = 0) 
     * @param method API method to call
     * @param paramsAsJson API method's parameters in JSON format
     * 
     * @return JSON string representing raw server response
     */
    static std::string backendRequest(
        const std::string& serverUrl, 
        const std::string& apiKeyId, 
        const std::string& apiKeySecret, 
        const int64_t mode,
        const std::string& method,
        const std::string& paramsAsJson
    );                            

private:
    static std::string _backendRequest(
        const std::string& serverUrl,
        const std::vector<std::pair<std::string, std::string>> headers, 
        const std::string& method, 
        const std::string& paramsAsJson
    );
    static std::string getED25519KeyFromPEM(const std::string& keyPEM);
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_BACKENDREQUESTER_HPP_
