/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_PRIVMXCLI_VARS_FUN_ENUM_HPP_
#define _PRIVMXLIB_ENDPOINT_PRIVMXCLI_VARS_FUN_ENUM_HPP_

namespace privmx {
namespace endpoint {
namespace privmxcli {

enum func_enum {
    //internal
    nonfunc,
    quit,
    falias,
    salias,
    scopy,
    sset,
    ssetArray,
    sget,
    sreadFile,
    swriteFile,
    help,
    loopStart,
    loopStop,
    a_sleep,
    addFront,
    addBack,
    addFrontString,
    addBackString,
    use,
    //server bridge
    bridge_setBridgeApiCreds,
    bridge_manager_auth,
    bridge_manager_createApiKey,
    bridge_manager_getApiKey,
    bridge_manager_listApiKeys,
    bridge_manager_updateApiKey,
    bridge_manager_deleteApiKey,
    bridge_solution_getSolution,
    bridge_solution_listSolutions,
    bridge_solution_createSolution,
    bridge_solution_updateSolution,
    bridge_solution_deleteSolution,
    bridge_context_getContext,
    bridge_context_listContexts,
    bridge_context_listContextsOfSolution,
    bridge_context_createContext,
    bridge_context_updateContext,
    bridge_context_deleteContext,
    bridge_context_addSolutionToContext,
    bridge_context_removeSolutionFromContext,
    bridge_context_addUserToContext,
    bridge_context_removeUserFromContext,
    bridge_context_removeUserFromContextByPubKey,
    bridge_context_getUserFromContext,
    bridge_context_getUserFromContextByPubKey,
    bridge_context_listUsersFromContext,
    bridge_context_setUserAcl,
    //endpoint
    //  config
    config_setCertsPath,
    //  core
    core_waitEvent,
    core_getEvent,
    core_emitBreakEvent,
    core_connect,
    core_connectPublic,
    core_disconnect,
    core_getConnectionId,
    core_listContexts,
    core_backendRequest,
    //  crypto
    crypto_signData,
    crypto_verifySignature,
    crypto_generatePrivateKey,
    crypto_derivePrivateKey,
    crypto_derivePublicKey,
    crypto_generateKeySymmetric,
    crypto_encryptDataSymmetric,
    crypto_decryptDataSymmetric,
    crypto_convertPEMKeytoWIFKey,
    //  thread
    thread_createThread,
    thread_updateThread,
    thread_getThread,
    thread_listThreads,
    thread_deleteThread,
    thread_sendMessage,
    thread_updateMessage,
    thread_getMessage,
    thread_listMessages,
    thread_deleteMessage,
    thread_subscribeForThreadEvents,
    thread_unsubscribeFromThreadEvents,
    thread_subscribeForMessageEvents,
    thread_unsubscribeFromMessageEvents,
    //  store
    store_createStore,
    store_updateStore,
    store_getStore,
    store_listStores,
    store_deleteStore,
    store_createFile,
    store_updateFile,
    store_updateFileMeta,
    store_getFile,
    store_listFiles,
    store_deleteFile,
    store_openFile,
    store_readFromFile,
    store_writeToFile,
    store_seekInFile,
    store_closeFile,
    store_subscribeForStoreEvents,
    store_unsubscribeFromStoreEvents,
    store_subscribeForFileEvents,
    store_unsubscribeFromFileEvents,
    //  inbox
    inbox_createInbox,
    inbox_updateInbox,
    inbox_getInbox,
    inbox_listInboxes,
    inbox_deleteInbox,
    inbox_getInboxPublicView,
    inbox_prepareEntry,
    inbox_sendEntry,
    inbox_readEntry,
    inbox_listEntries,
    inbox_deleteEntry,
    inbox_createFileHandle,
    inbox_writeToFile,
    inbox_openFile,
    inbox_readFromFile,
    inbox_seekInFile,
    inbox_closeFile,
    inbox_subscribeForInboxEvents,
    inbox_unsubscribeFromInboxEvents,
    inbox_subscribeForEntryEvents,
    inbox_unsubscribeFromEntryEvents
};

} // privmxcli
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_PRIVMXCLI_VARS_FUN_ENUM_HPP_