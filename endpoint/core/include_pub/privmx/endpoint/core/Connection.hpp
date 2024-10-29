#ifndef _PRIVMXLIB_ENDPOINT_CORE_CONNECTION_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CONNECTION_HPP_

#include <memory>
#include <string>

#include "privmx/endpoint/core/Types.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class ConnectionImpl;

/**
 * 'Connection' represents and manages the current connection between the Endpoint and the Bridge server.
 */
class Connection {
public:
    /**
     * Connects to the PrivMX Bridge server.
     *
     * @param userPrivKey user's private key
     * @param solutionId ID of the Solution
     * @param platformUrl Platform's Endpoint URL
     * 
     * @return Connection object
     */
    static Connection platformConnect(const std::string& userPrivKey, const std::string& solutionId,
                                      const std::string& platformUrl);

    /**
     * Connects to the PrivMX Bridge Server as a guest user.
     *
     * @param solutionId ID of the Solution
     * @param platformUrl Platform's Endpoint URL
     * 
     * @return Connection object
     */                                     
    static Connection platformConnectPublic(const std::string& solutionId, const std::string& platformUrl);
    
    /**
     * //doc-gen:ignore
     */
    Connection() = default;

    /**
     * Gets the ID of the current connection.
     * 
     * @return ID of the connection
     */ 
    int64_t getConnectionId();

    /**
     * Gets a list of Contexts available for the user.
     * 
     * @param pagingQuery struct with list query parameters
     * 
     * @return struct containing a list of Contexts
     */
    PagingList<Context> listContexts(const PagingQuery& pagingQuery);

    /**
     * Disconnects from the PrivMX Bridge server.
     *
     */
    void disconnect();

    std::shared_ptr<ConnectionImpl> getImpl() const { return _impl; }

private:
    void validateEndpoint();
    Connection(const std::shared_ptr<ConnectionImpl>& impl);
    std::shared_ptr<ConnectionImpl> _impl;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_CONNECTION_HPP_
