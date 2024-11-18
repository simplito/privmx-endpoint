/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_PRIVMXCLI_VARS_FUN_MAP_HPP_
#define _PRIVMXLIB_ENDPOINT_PRIVMXCLI_VARS_FUN_MAP_HPP_


#include <string>
#include <unordered_map>
#include "privmx/endpoint/programs/privmxcli/vars/function_enum.hpp"

namespace privmx {
namespace endpoint {
namespace privmxcli {

inline std::unordered_map<std::string, func_enum> functions_internal = {
    {"quit", quit},
    {"exit", quit},
    {"falias", falias},
    {"alias", salias},
    {"copy", scopy},
    {"set", sset},
    // {"setArray", ssetArray},
    {"get", sget},
    {"setFromFile", sreadFile},
    {"saveToFile", swriteFile},
    {"help", help},
    {"loopStart", loopStart},
    {"loopStop", loopStop},
    {"sleep", a_sleep},
    {"addFront", addFront},
    {"addBack", addBack},
    {"addFrontString", addFrontString},
    {"addBackString", addBackString},
    {"use", use}
};

inline std::unordered_map<std::string, func_enum> functions_bridge = {
    {"bridge.setBridgeApiCreds", bridge_setBridgeApiCreds},
    {"bridge.manager.auth", bridge_manager_auth},
    {"bridge.manager.createApiKey", bridge_manager_createApiKey},
    {"bridge.manager.getApiKey", bridge_manager_getApiKey},
    {"bridge.manager.listApiKeys", bridge_manager_listApiKeys},
    {"bridge.manager.updateApiKey", bridge_manager_updateApiKey},
    {"bridge.manager.deleteApiKey", bridge_manager_deleteApiKey},
    {"bridge.solution.getSolution", bridge_solution_getSolution},
    {"bridge.solution.listSolutions", bridge_solution_listSolutions},
    {"bridge.solution.createSolution", bridge_solution_createSolution},
    {"bridge.solution.updateSolution", bridge_solution_updateSolution},
    {"bridge.solution.deleteSolution", bridge_solution_deleteSolution},
    {"bridge.context.getContext", bridge_context_getContext},
    {"bridge.context.listContexts", bridge_context_listContexts},
    {"bridge.context.listContextsOfSolution", bridge_context_listContextsOfSolution},
    {"bridge.context.createContext", bridge_context_createContext},
    {"bridge.context.updateContext", bridge_context_updateContext},
    {"bridge.context.deleteContext", bridge_context_deleteContext},
    {"bridge.context.addSolutionToContext", bridge_context_addSolutionToContext},
    {"bridge.context.removeSolutionFromContext", bridge_context_removeSolutionFromContext},
    {"bridge.context.addUserToContext", bridge_context_addUserToContext},
    {"bridge.context.removeUserFromContext", bridge_context_removeUserFromContext},
    {"bridge.context.removeUserFromContextByPubKey", bridge_context_removeUserFromContextByPubKey},
    {"bridge.context.getUserFromContext", bridge_context_getUserFromContext},
    {"bridge.context.getUserFromContextByPubKey", bridge_context_getUserFromContextByPubKey},
    {"bridge.context.listUsersFromContext", bridge_context_listUsersFromContext},
    {"bridge.context.setUserAcl", bridge_context_setUserAcl},
};

inline const std::unordered_map<std::string, func_enum> functions_endpoint = {
    //endpoint
    {"config.setCertsPath", config_setCertsPath},
    {"core.waitEvent", core_waitEvent},
    {"core.getEvent", core_getEvent},
    {"core.emitBreakEvent", core_emitBreakEvent},
    {"core.connect", core_connect},
    {"core.connectPublic", core_connectPublic},
    {"core.disconnect", core_disconnect},
    {"core.getConnectionId", core_getConnectionId},
    {"core.listContexts", core_listContexts},
    {"core.backendRequest", core_backendRequest},
    {"crypto.signData", crypto_signData},
    {"crypto.verifySignature", crypto_verifySignature},
    {"crypto.generatePrivateKey", crypto_generatePrivateKey},
    {"crypto.derivePrivateKey", crypto_derivePrivateKey},
    {"crypto.derivePublicKey", crypto_derivePublicKey},
    {"crypto.generateKeySymmetric", crypto_generateKeySymmetric},
    {"crypto.encryptDataSymmetric", crypto_encryptDataSymmetric},
    {"crypto.decryptDataSymmetric", crypto_decryptDataSymmetric},
    {"crypto.convertPEMKeytoWIFKey", crypto_convertPEMKeytoWIFKey},
    {"thread.createThread", thread_createThread},
    {"thread.updateThread", thread_updateThread},
    {"thread.getThread", thread_getThread},
    {"thread.listThreads", thread_listThreads},
    {"thread.deleteThread", thread_deleteThread},
    {"thread.sendMessage", thread_sendMessage},
    {"thread.updateMessage", thread_updateMessage},
    {"thread.getMessage", thread_getMessage},
    {"thread.listMessages", thread_listMessages},
    {"thread.deleteMessage", thread_deleteMessage},
    {"thread.subscribeForThreadEvents", thread_subscribeForThreadEvents},
    {"thread.unsubscribeFromThreadEvents", thread_unsubscribeFromThreadEvents},
    {"thread.subscribeForMessageEvents", thread_subscribeForMessageEvents},
    {"thread.unsubscribeFromMessageEvents", thread_unsubscribeFromMessageEvents},
    {"store.createStore", store_createStore},
    {"store.updateStore", store_updateStore},
    {"store.getStore", store_getStore},
    {"store.listStores", store_listStores},
    {"store.deleteStore", store_deleteStore},
    {"store.createFile", store_createFile},
    {"store.updateFile", store_updateFile},
    {"store.updateFileMeta", store_updateFileMeta},
    {"store.getFile", store_getFile},
    {"store.listFiles", store_listFiles},
    {"store.deleteFile", store_deleteFile},
    {"store.openFile", store_openFile},
    {"store.readFromFile", store_readFromFile},
    {"store.writeToFile", store_writeToFile},
    {"store.seekInFile", store_seekInFile},
    {"store.closeFile", store_closeFile},
    {"store.subscribeForStoreEvents", store_subscribeForStoreEvents},
    {"store.unsubscribeFromStoreEvents", store_unsubscribeFromStoreEvents},
    {"store.subscribeForFileEvents", store_subscribeForFileEvents},
    {"store.unsubscribeFromFileEvents", store_unsubscribeFromFileEvents},
    {"inbox.createInbox", inbox_createInbox},
    {"inbox.updateInbox", inbox_updateInbox},
    {"inbox.getInbox", inbox_getInbox},
    {"inbox.listInboxes", inbox_listInboxes},
    {"inbox.deleteInbox", inbox_deleteInbox},
    {"inbox.getInboxPublicView", inbox_getInboxPublicView},
    {"inbox.prepareEntry", inbox_prepareEntry},
    {"inbox.sendEntry", inbox_sendEntry},
    {"inbox.readEntry", inbox_readEntry},
    {"inbox.listEntries", inbox_listEntries},
    {"inbox.deleteEntry", inbox_deleteEntry},
    {"inbox.createFileHandle", inbox_createFileHandle},
    {"inbox.writeToFile", inbox_writeToFile},
    {"inbox.openFile", inbox_openFile},
    {"inbox.readFromFile", inbox_readFromFile},
    {"inbox.seekInFile", inbox_seekInFile},
    {"inbox.closeFile", inbox_closeFile},
    {"inbox.subscribeForInboxEvents", inbox_subscribeForInboxEvents},
    {"inbox.unsubscribeFromInboxEvents",  inbox_unsubscribeFromInboxEvents},
    {"inbox.subscribeForEntryEvents", inbox_subscribeForEntryEvents},
    {"inbox.unsubscribeFromEntryEvents", inbox_unsubscribeFromEntryEvents},
};

} // privmxcli
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_PRIVMXCLI_VARS_FUN_MAP_HPP_