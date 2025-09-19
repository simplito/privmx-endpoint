#ifndef _PRIVMXLIB_ENDPOINT_THREAD_THREADAPI_TYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_THREADAPI_TYPES_HPP_

#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/core/Types.hpp"


namespace privmx {
namespace endpoint {
namespace thread {

/**
 * Holds message's information created by server.
 */
struct ServerMessageInfo {
    /**
     * ID of the Thread
     */
    std::string threadId;

    /**
     * ID of the message
     */
    std::string messageId;

    /**
     * message's creation timestamp
     */
    int64_t createDate;

    /**
     * ID of the user who created the message
     */
    std::string author;
};

/**
 * Holds information about the Message.
 */
struct Message {
    /**
     * message's information created by server
     */
    ServerMessageInfo info;

    /**
     * message's public metadata
     */
    core::Buffer publicMeta;

    /**
     * message's private metadata
     */
    core::Buffer privateMeta;

    /**
     * message's data
     */
    core::Buffer data;

    /**
     * public key of an author of the message
     */
    std::string authorPubKey;

    /**
     * status code of retrieval and decryption of the message
     */
    int64_t statusCode;

    /**
     * Version of the Message data structure and how it is encoded/encrypted
     */
    int64_t schemaVersion;
};


/**
 * Holds all available information about a Thread.
 */
struct Thread {

    /**
     * ID of the Context
     */
    std::string contextId;

    /**
     * ID of the Thread
     */
    std::string threadId;

    /**
     * Thread creation timestamp
     */
    int64_t createDate;

    /**
     * ID of user who created the Thread
     */
    std::string creator;

    /**
     * Thread last modification timestamp
     */
    int64_t lastModificationDate;

    /**
     * ID of the user who last modified the Thread
     */
    std::string lastModifier;

    /**
     * list of users (their IDs) with access to the Thread
     */
    std::vector<std::string> users;

    /**
     * list of users (their IDs) with management rights
     */
    std::vector<std::string> managers;

    /**
     * version number (changes on updates)
     */
    int64_t version;

    /**
     * timestamp of last posted message
     */
    int64_t lastMsgDate;

    /**
     * Thread's public metadata
     */
    core::Buffer publicMeta;

    /**
     * Thread's private metadata
     */
    core::Buffer privateMeta;

    /**
     * Thread's policies
     */
    core::ContainerPolicy policy;

    /**
     * total number of messages in the Thread
     */
    int64_t messagesCount;

    /**
     * status code of retrieval and decryption of the Thread
     */
    int64_t statusCode;

    /**
     * Version of the Thread data structure and how it is encoded/encrypted
     */
    int64_t schemaVersion;
};

enum EventType: int64_t {
    THREAD_CREATE = 0,
    THREAD_UPDATE = 1,
    THREAD_DELETE = 2,
    THREAD_STATS = 3,
    MESSAGE_CREATE = 4,
    MESSAGE_UPDATE = 5,
    MESSAGE_DELETE = 6,
    COLLECTION_CHANGE = 7,
};

enum EventSelectorType: int64_t {
    CONTEXT_ID = 0,
    THREAD_ID = 1,
    MESSAGE_ID = 2,
};

}  // namespace thread
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_THREAD_THREADAPI_TYPES_HPP_
