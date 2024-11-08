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

inline const std::unordered_map<std::string, func_enum> functions = {
    //endpoint
    {"waitEvent", waitEvent},
    {"getEvent", getEvent},
    {"platformConnect", platformConnect},
    {"platformDisconnect", platformDisconnect},
    {"contextList", contextList},
    {"threadCreate", threadCreate},
    {"threadGet", threadGet},
    {"threadList", threadList},
    {"threadMessageSend", threadMessageSend},
    {"threadMessagesGet", threadMessagesGet},
    {"storeList", storeList},
    {"storeGet", storeGet},
    {"storeCreate", storeCreate},
    {"storeFileGet", storeFileGet},
    {"storeFileList", storeFileList},
    {"storeFileCreate", storeFileCreate},
    {"storeFileUpdate", storeFileUpdate},
    {"storeFileOpen", storeFileOpen},
    {"storeFileRead", storeFileRead},
    {"storeFileWrite", storeFileWrite},
    {"storeFileSeek", storeFileSeek},
    {"storeFileClose", storeFileClose},
    {"storeFileDelete", storeFileDelete},
    {"cryptoPrivKeyNew", cryptoPrivKeyNew},
    {"cryptoPubKeyNew", cryptoPubKeyNew},
    {"cryptoEncrypt", cryptoEncrypt},
    {"cryptoDecrypt", cryptoDecrypt},
    {"cryptoSign", cryptoSign},
    {"setCertsPath", setCertsPath},
    {"cryptoKeyConvertPEMToWIF", cryptoKeyConvertPEMToWIF},
    {"backendRequest", backendRequest},
    {"threadDelete", threadDelete},
    {"threadMessageDelete", threadMessageDelete},
    {"threadMessageGet", threadMessageGet},
    {"storeDelete", storeDelete},
    {"messageGet", messageGet},
    {"messagesGet", messagesGet},
    {"messageSend", messageSend},
    {"inboxCreate", inboxCreate},
    {"inboxUpdate", inboxUpdate},
    {"inboxGet", inboxGet},
    {"inboxList", inboxList},
    {"inboxPublicViewGet", inboxPublicViewGet},
    {"inboxCreateFileHandle", inboxCreateFileHandle},
    {"inboxSendPrepare", inboxSendPrepare},
    {"inboxSendFileDataChunk", inboxSendFileDataChunk},
    {"inboxSendCommit", inboxSendCommit},
    {"threadUpdate", threadUpdate},
    {"storeUpdate", storeUpdate},
    {"cryptoPrivKeyNewPbkdf2", cryptoPrivKeyNewPbkdf2},
    {"subscribeToChannel", subscribeToChannel},
    {"unsubscribeFromChannel", unsubscribeFromChannel},
    {"fileGet", fileGet},
    {"fileList", fileList},
    {"fileOpen", fileOpen},
    {"fileSeek", fileSeek},
    {"fileRead", fileRead},
    {"fileClose", fileClose},
    {"inboxFileGet", inboxFileGet},
    {"inboxFileList", inboxFileList},
    {"inboxFileOpen", inboxFileOpen},
    {"inboxFileSeek", inboxFileSeek},
    {"inboxFileRead", inboxFileRead},
    {"inboxFileClose", inboxFileClose},
    {"inboxMessageGet", inboxMessageGet},
    {"inboxMessagesGet", inboxMessagesGet},
    {"messageDelete", messageDelete},
    {"inboxDelete", inboxDelete}
};

#endif // _PRIVMXLIB_ENDPOINT_PRIVMXCLI_VARS_FUN_MAP_HPP_