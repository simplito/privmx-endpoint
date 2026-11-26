#ifndef _PRIVMXLIB_ENDPOINT_CORE_CONNECTION_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CONNECTION_HPP_

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "privmx/endpoint/core/BaseApiClass.hpp"
#include "privmx/endpoint/core/PinStoreInterface.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/core/UserVerifierInterface.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class ConnectionImpl;

/**
 * 'Connection' represents and manages the current connection between the Endpoint and the Bridge server.
 */
class Connection : public BaseApiClass<ConnectionImpl> {
public:
    /**
     * Connects to the PrivMX Bridge server.
     *
     * @param userPrivKey user's private key
     * @param solutionId ID of the Solution
     * @param bridgeUrl Bridge Server URL
     * @param verificationOptions PrivMX Bridge server instance verification options using a PKI server
     * 
     * @return Connection object
     */
    static Connection connect(
        const std::string& userPrivKey,
        const std::string& solutionId,
        const std::string& bridgeUrl,
        const PKIVerificationOptions& verificationOptions = PKIVerificationOptions()
    );

    /**
     * Connects to the PrivMX Bridge Server as a guest user.
     *
     * @param solutionId ID of the Solution
     * @param bridgeUrl Bridge Server URL
     * @param verificationOptions PrivMX Bridge server instance verification options using a PKI server
     * 
     * @return Connection object
     */
    static Connection connectPublic(
        const std::string& solutionId,
        const std::string& bridgeUrl,
        const PKIVerificationOptions& verificationOptions = PKIVerificationOptions()
    );

    /**
     * //doc-gen:ignore
     */
    Connection();
    Connection(const Connection& obj);
    Connection& operator=(const Connection& obj);
    Connection(Connection&& obj);
    ~Connection();

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
     * Gets a list of users with their status and the last status change.
     * 
     * @param contextId ID of the Context
     * 
     * @return List of users with their status and the last status change
    */
    PagingList<UserInfo> listContextUsers(const std::string& contextId, const PagingQuery& pagingQuery);

    /**
     * Subscribe for the Context events on the given subscription query.
     * 
     * @param subscriptionQueries List of queries
     * @return List of subscriptionIds in matching order to subscriptionQueries
     */
    std::vector<std::string> subscribeFor(const std::vector<std::string>& subscriptionQueries);

    /**
     * Unsubscribe from events for the given subscriptionId.
     * @param subscriptionIds List of subscriptionId
     */
    void unsubscribeFrom(const std::vector<std::string>& subscriptionIds);

    /**
     * Generate subscription Query for the Context events.
     * @param eventType type of event which you listen for
     * @param selectorType scope on which you listen for events  
     * @param selectorId ID of the selector
     */
    std::string buildSubscriptionQuery(
        EventType eventType,
        EventSelectorType selectorType,
        const std::string& selectorId
    );

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
     * e.g. Developer's Application Server or PKI Server.
     * Without a service to ask, useKeyContinuity gives a verifier that needs none.
     *
     * @param verifier an implementation of the UserVerifierInterface
     * 
     */
    void setUserVerifier(std::shared_ptr<UserVerifierInterface> verifier);

    /**
     * Sets where the library keeps state between sessions (key-tree pins of the groups this device verified). Without
     * a store every new GroupApi reads each group on trust once (TOFU); with one, only the first contact of this device
     * with a group does.
     *
     * Call it right after `connect`, before creating any module API: a GroupApi reads the store once, when it is
     * created. Slots are per identity key and per Bridge (URL, public key and instance id of `connect`). The store
     * must be local to the device: one the Bridge can write lets the Bridge delete the saved state (protection back to
     * first contact) or roll it back to an older saved one (it can never plant a state). Ignored on a `connectPublic`
     * connection. See PinStoreInterface for the atomicity and threading contract.
     *
     * A slot that does not load (the store throws) or fails its integrity check is logged as a warning and ignored:
     * that GroupApi starts as a first contact for every group, as without a store, and the next save overwrites the
     * slot. Nothing is thrown, so a corrupted store never locks the app out of its groups.
     * @param store an implementation of the PinStoreInterface, or nullptr to keep state in memory only
     */
    void setPinStore(std::shared_ptr<PinStoreInterface> store);

    /**
     * After the user's identity key changed: carries the pins the store holds for the previous key over to the
     * current one, for every GroupApi created afterwards. A pin of the previous key is taken only for a group with no
     * pin under the current key, and only as a hint: it never replaces or raises one, and is saved under the current
     * key only once a read has replayed the group's chain to it. A group whose served chain does not reach the hint is
     * refused as a fork (GroupHistoryForkException) in every session that adopts it; the app recovers by deleting the
     * previous key's slot from its PinStore, after which the group is read on trust once, as on first contact.
     * Call it right after `connect` and `setPinStore`, before creating any module API, and again on every later start
     * (every new connection) for as long as the previous key's slot is kept: the hints and the key-change knowledge
     * live in this connection's memory only, so a start that skips the call reads a group whose hint no read has
     * verified yet as a first contact, and lets a removal abandon history again. Without a store, or nothing
     * stored for the previous key, nothing is carried over. Either way it tells this client its key changed: a
     * GroupApi::removeGroupMembers whose own leaf does not open but opens with the previous key is then refused until
     * GroupApi::renewLeaf, instead of abandoning the group's history.
     * @param previousUserPrivKey the previous identity private key in WIF
     * @throws LocalStateIntegrityException when the previous key's stored pins fail their integrity check. The app
     * may deliberately delete that slot (the previous key's) from its PinStore and call again, accepting that groups
     * without a pin under the current key are then read on trust once, as on first contact.
     */
    void adoptPreviousIdentity(const std::string& previousUserPrivKey);

    /**
     * After the user's identity key changed and the previous one is still at hand: adoptPreviousIdentity, and from
     * then on every GroupApi of this connection re-wraps the caller's own leaf to the current key by itself, the
     * first time it reads a Group whose leaf the current key does not open (what GroupApi::renewLeaf does for one
     * Group on request). Call it where adoptPreviousIdentity would be called: right after `connect` and
     * `setPinStore`, on every start for as long as some Group may still be waiting.
     *
     * Without the previous key there is nothing to renew with: another member lets the user back in with
     * GroupApi::reseatGroupMembers.
     * @param previousUserPrivKey the previous identity private key in WIF
     * @throws LocalStateIntegrityException as adoptPreviousIdentity
     */
    void renewIdentity(const std::string& previousUserPrivKey);

    /**
     * Sets the built-in key-continuity verifier as this connection's UserVerifier: the first key a user of a Context
     * is seen with is taken as theirs (trust on first use) if it is the key the Bridge lists for that user in that
     * Context and is not already taken as another user's there, and any other key for that user is refused until
     * acceptKeyChange. The first key is the Bridge's word, never the one a signed item names for its own author; a
     * user the Bridge no longer lists (removed from the Context) is refused on first use. For an application with no
     * server or PKI of its own to ask; one that has such a service should implement UserVerifierInterface instead,
     * which also covers the first key.
     *
     * Not the default, and not free of consequences. What it knows lives in this connection's memory, so every new
     * connection trusts first use again and has to be told again of every change it must accept. And a user whose key
     * changed is refused wherever both keys appear: in a Group's history after a leaf renewal, or on an item one user
     * wrote and another edited (the item is checked as its author's id with the editor's key). A user removed from
     * the Context is refused on first use, so a Group whose statements they signed (its latest committer, say) is
     * unreadable on every new connection. On a `connectPublic` connection, or for a user without permission to list
     * the Context's users, the Bridge lists nobody and only the connection's own user is accepted. Call it right after
     * `connect`, before creating any module API.
     */
    void useKeyContinuity();

    /**
     * Tells this connection that a user's identity key changed, and that the application has checked the change.
     * For a connection that keeps to key continuity (useKeyContinuity).
     *
     * After this call `newPubKey` is the user's key; `previousPubKey` stays good for what is dated before this call,
     * and for nothing dated later. The knowledge lives in this connection's memory.
     *
     * A GroupApi envelope is checked as of now, not as of the date it claims (that date is the signer's word, and a
     * stolen retired key could backdate it): an envelope signed with `previousPubKey` is refused once this call
     * retired it, as it is after Connection::renewIdentity. Re-encrypt what must stay readable before the change.
     *
     * @param contextId ID of the Context the user belongs to
     * @param userId ID of the user
     * @param previousPubKey the key the user had, in Base58DER
     * @param newPubKey the key the user has now, in Base58DER
     * @throws InvalidParamsException when `previousPubKey` is not the key this connection knows the user by, or when
     * key continuity is not on: the application's own UserVerifier decides then, and is the thing to update
     */
    void acceptKeyChange(
        const std::string& contextId,
        const std::string& userId,
        const std::string& previousPubKey,
        const std::string& newPubKey
    );

private:
    void assertGateway(const std::shared_ptr<ConnectionImpl>& impl);
    void assertConnection(const std::shared_ptr<ConnectionImpl>& impl);
    Connection(const std::shared_ptr<ConnectionImpl>& impl);
    std::optional<int64_t> _connectionId;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_CONNECTION_HPP_
