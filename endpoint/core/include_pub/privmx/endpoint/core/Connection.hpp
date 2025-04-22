#ifndef _PRIVMXLIB_ENDPOINT_CORE_CONNECTION_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CONNECTION_HPP_

#include <memory>
#include <string>

#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/core/UserVerifierInterface.hpp"

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
     * @param bridgeUrl Bridge Server URL
     * 
     * @return Connection object
     */
    static Connection connect(const std::string& userPrivKey, const std::string& solutionId,
                              const std::string& bridgeUrl, const PKIVerificationOptions& verificationOptions = PKIVerificationOptions());

    /**
     * Connects to the PrivMX Bridge Server as a guest user.
     *
     * @param solutionId ID of the Solution
     * @param bridgeUrl Bridge Server URL
     * 
     * @return Connection object
     */                                     
    static Connection connectPublic(const std::string& solutionId, const std::string& bridgeUrl, 
                                    const PKIVerificationOptions& verificationOptions = PKIVerificationOptions());
    
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
     * Gets a list of users of given context.
     * 
     * @param contextId ID of the context
     * 
     * @return vector containing a list of users Info
     */
    std::vector<UserInfo> getContextUsers(const std::string& contextId);

    /**
     * Disconnects from the PrivMX Bridge server.
     *
     */
    void disconnect();

    /**
     * Sets user's custom verification callback.
     * 
     * The feature allows the developer to set up a callback for user verification. 
     * A developer can implement an interface and pass the implementation to the function. 
     * Each time data is read from the container, a callback will be triggered, allowing the developer to validate the sender in an external service,
     * e.g. Developers Application Server or PKI Server
     * @param verifier an implementation of the UserVerifierInterface
     * 
     */
    void setUserVerifier(std::shared_ptr<UserVerifierInterface> verifier);

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
