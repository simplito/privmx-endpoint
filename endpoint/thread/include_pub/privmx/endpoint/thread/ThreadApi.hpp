#ifndef _PRIVMXLIB_ENDPOINT_THREAD_THREADAPI_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_THREADAPI_HPP_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "privmx/endpoint/core/Connection.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/thread/Types.hpp"

namespace privmx {
namespace endpoint {
namespace thread {

class ThreadApiImpl;

/**
 * 'ThreadApi' is a class representing Endpoint's API for Threads and their messages.
 */
class ThreadApi {
public:
    /**
     * Creates an instance of 'ThreadApi'.
     * 
     * @param connection instance of 'Connection'
     * 
     * @return ThreadApi object
     */
    static ThreadApi create(core::Connection& connetion);

    /**
     * //doc-gen:ignore
     */
    ThreadApi() = default;

    /**
     * Creates a new Thread in given Context.
     *
     * @param contextId ID of the Context to create the Thread in
     * @param users vector of UserWithPubKey structs which indicates who will have access to the created Thread
     * @param managers vector of UserWithPubKey structs which indicates who will have access (and management rights) to
     * the created Thread
     * @param publicMeta public (unencrypted) metadata
     * @param privateMeta private (encrypted) metadata
     * @param policies Thread's policies
     * @return ID of the created Thread
     */
    std::string createThread(const std::string& contextId, const std::vector<core::UserWithPubKey>& users,
                             const std::vector<core::UserWithPubKey>& managers, const core::Buffer& publicMeta, 
                             const core::Buffer& privateMeta, const std::optional<core::ContainerPolicy>& policies = std::nullopt);
    
    /**
     * Updates an existing Thread.
     *
     * @param threadId ID of the Thread to update
     * @param users vector of UserWithPubKey structs which indicates who will have access to the created Thread
     * @param managers vector of UserWithPubKey structs which indicates who will have access (and management rights) to
     * the created Thread
     * @param publicMeta public (unencrypted) metadata
     * @param privateMeta private (encrypted) metadata
     * @param version current version of the updated Thread
     * @param force force update (without checking version)
     * @param forceGenerateNewKey force to regenerate a key for the Thread
     * @param policies Thread's policies
     */
    void updateThread(const std::string& threadId, const std::vector<core::UserWithPubKey>& users,
                      const std::vector<core::UserWithPubKey>& managers, const core::Buffer& publicMeta, const core::Buffer& privateMeta,
                      const int64_t version, const bool force, const bool forceGenerateNewKey, const std::optional<core::ContainerPolicy>& policies = std::nullopt);

    /**
     * Deletes a Thread by given Thread ID.
     *
     * @param threadId ID of the Thread to delete
     */
    void deleteThread(const std::string& threadId);

    /**
     * Gets a Thread by given Thread ID.
     *
     * @param threadId ID of Thread to get
     * @return Thread struct containing info about the Thread
     */
    Thread getThread(const std::string& threadId);

    /**
     * Gets a list of Threads in given Context.
     *
     * @param contextId ID of the Context to get the Threads from
     * @param pagingQuery struct with list query parameters
     * @return struct containing a list of Threads
     */
    core::PagingList<Thread> listThreads(const std::string& contextId, const core::PagingQuery& pagingQuery);
    
    /**
     * Gets a message by given message ID.
     *
     * @param ID of the message to get
     * @return struct containing the message
     */
    Message getMessage(const std::string& messageId);
    
    /**
     * Gets a list of messages from a Thread.
     *
     * @param threadId ID of the Thread to list messages from
     * @param pagingQuery struct with list query parameters
     * @return struct containing a list of messages
     */
    core::PagingList<Message> listMessages(const std::string& threadId, const core::PagingQuery& pagingQuery);
    
    /**
     * Sends a message in a Thread.
     *
     * @param threadId ID of the Thread to send message to
     * @param publicMeta public message metadata
     * @param privateMeta private message metadata
     * @param data content of the message
     * @return ID of the new message
     */
    std::string sendMessage(const std::string& threadId, const core::Buffer& publicMeta,
                            const core::Buffer& privateMeta, const core::Buffer& data);
    
    /**
     * Deletes a message by given message ID.
     *
     * @param messageId ID of the message to delete
     */
    void deleteMessage(const std::string& messageId);

    /**
     * Update message in a Thread.
     *
     * @param messageId ID of the message to update
     * @param publicMeta public message metadata
     * @param privateMeta private message metadata
     * @param data content of the message
     */
    void updateMessage(const std::string& messageId, const core::Buffer& publicMeta,
                            const core::Buffer& privateMeta, const core::Buffer& data);

    /**
     * Subscribes for the Thread module main events.
     */
    void subscribeForThreadEvents();

    /**
     * Unsubscribes from the Thread module main events.
     */
    void unsubscribeFromThreadEvents();

    /**
     * Subscribes for events in given Thread.
     * @param thread ID of the Thread to subscribe
     */    
    void subscribeForMessageEvents(const std::string& threadId);

    /**
     * Unsubscribes from events in given Thread.
     * @param thread ID of the Thread to unsubscribe
     */    
    void unsubscribeFromMessageEvents(const std::string& threadId);

    /**
     * Emit Custom Event for selected group users of Thread.
     * 
     * @param threadId ID of the Thread on witch event will be send
     * @param channelName name of event channel
     * @param eventData encrypted event data
     * @param usersIds list of userId for which event will be send 
     */
    void emitEvent(const std::string& threadId, const std::string& channelName, const core::Buffer& eventData, const std::vector<std::string>& usersIds);
    
    /**
     * Subscribes for custom events in given Thread on given channel.
     * @param thread ID of the Thread to subscribe
     * @param channelName name of the channel to subscribe
     */ 
    void subscribeForThreadCustomEvents(const std::string& threadId, const std::string& channelName);

     /**
     * Unsubscribes from custom events in given Thread on given channel.
     * @param thread ID of the Thread to unsubscribe
     * @param channelName name of the channel to unsubscribe
     */ 
    void unsubscribeFromThreadCustomEvents(const std::string& threadId, const std::string& channelName);

    std::shared_ptr<ThreadApiImpl> getImpl() const { return _impl; }
    
private:
    void validateEndpoint();
    ThreadApi(const std::shared_ptr<ThreadApiImpl>& impl);
    std::shared_ptr<ThreadApiImpl> _impl;
};

}  // namespace thread
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_THREAD_THREADAPI_HPP_
