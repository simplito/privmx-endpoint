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
    //endpoint
    waitEvent,
    getEvent,
    platformConnect,
    platformDisconnect,
    contextList,
    threadCreate,
    threadGet,
    threadList,
    threadMessageSend,
    threadMessagesGet,
    storeList,
    storeGet,
    storeCreate,
    storeFileGet,
    storeFileList,
    storeFileCreate,
    storeFileUpdate,
    storeFileOpen,
    storeFileRead,
    storeFileWrite,
    storeFileSeek,
    storeFileClose,
    storeFileDelete,
    cryptoPrivKeyNew,
    cryptoPubKeyNew,
    cryptoEncrypt,
    cryptoDecrypt,
    cryptoSign,
    setCertsPath,
    cryptoKeyConvertPEMToWIF,
    backendRequest,
    threadDelete,
    threadMessageDelete,
    threadMessageGet,
    storeDelete,
    messageGet,
    messagesGet,
    messageSend,
    inboxCreate,
    inboxUpdate,
    inboxGet,
    inboxList,
    inboxPublicViewGet,
    inboxCreateFileHandle,
    inboxSendPrepare,
    inboxSendFileDataChunk,
    inboxSendCommit,
    threadUpdate,
    storeUpdate,
    cryptoPrivKeyNewPbkdf2,
    subscribeToChannel,
    unsubscribeFromChannel,
    fileGet,
    fileList,
    fileOpen,
    fileSeek,
    fileRead,
    fileClose,
    inboxFileGet,
    inboxFileList,
    inboxFileOpen,
    inboxFileSeek,
    inboxFileRead,
    inboxFileClose,
    inboxMessageGet,
    inboxMessagesGet,
    messageDelete,
    inboxDelete
};

#endif // _PRIVMXLIB_ENDPOINT_PRIVMXCLI_VARS_FUN_ENUM_HPP_