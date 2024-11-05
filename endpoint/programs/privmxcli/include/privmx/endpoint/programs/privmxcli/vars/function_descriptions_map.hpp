/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_PRIVMXCLI_VARS_FUN_HELP_HPP_
#define _PRIVMXLIB_ENDPOINT_PRIVMXCLI_VARS_FUN_HELP_HPP_


#include <string>
#include <unordered_map>
#include "privmx/endpoint/programs/privmxcli/vars/function_enum.hpp"

namespace privmx {
namespace endpoint {
namespace privmxcli {

inline const std::unordered_map<func_enum, std::string> functions_internal_help_description = {
    {quit, "quit"},
    {falias, 
        "falias NEW_ALIAS FUNCTION_NAME\n"
        "\tFunction  alias"
    },
    {salias, 
        "alias NEW_ALIAS, VAR_NAME\n"
        "\tVar alias"
    },
    {scopy, 
        "copy NEW_VAR, VAR_NAME\n"
        "\tVar copy"
    },
    {sset, 
        "set VAR_NAME, VAR_VALUE\n"
        "\tSet new var"
    },
    // {ssetArray, "setArray ARRAY_NAME VAR_VALUE ..."},
    {sget, 
        "get VAR_NAME"
    },
    {sreadFile, 
        "setFromFile VAR_NAME path"
    },
    {swriteFile, 
        "saveToFile VAR_NAME path"
    },
    {help, 
        "help FUNCTION_NAME\n"
        "\talso you can use ? afer function name to get help"
    },
    {loopStart, 
        "loopStart N OPTIONAL<ID>\n"
        "\tloops everything N times to loopStop\n"
        "\tId is optional"
    },
    {loopStop, 
        "loopStop"
    },
    {a_sleep, 
        "sleep T\n"
        "\tsleep for T ms\n"
        "sleep(T1,T2)\n"
        "\tsleep for random time between T1 T2ms"
    },
    {addFront, 
        "addFront VAR_NAME_1 VAR_NAME_2)\n"
        "\tadd second var on the front of the first var"
    },
    {addBack, 
        "addBack VAR_NAME_1 VAR_NAME_2\n"
        "\tadd second var on the back of the first var"
    },
    {addFrontString, 
        "addFront VAR_NAME, DATA_STRING)\n"
        "\tadd DATA_STRING on the front of var"
    },
    {addBackString, 
        "addBack VAR_NAME, DATA_STRING)\n"
        "\tadd DATA_STRING on the back of var"
    }
};

inline const std::unordered_map<func_enum, std::string> functions_internal_help_short_description = {
    {quit, "quit"},
    {falias, "create function alias"},
    {salias, "create var alias"},
    {scopy, "copy var"},
    {sset, "Set new var"},
    // {ssetArray, "setArray ARRAY_NAME VAR_VALUE ..."},
    {sget, "gets var"},
    {sreadFile, "reads from file"},
    {swriteFile, "write to file"},
    {help, "help"},
    {loopStart, "marker to start loop"},
    {loopStop, "marker to stop loop"},
    {a_sleep, "sleep for"},
    {addFront, "add var on the front of the other"},
    {addBack, "add var on the back of the other"},
    {addFrontString, "add string on the front of var"},
    {addBackString, "add string on the front of var"}
};

inline const std::unordered_map<func_enum, std::string> functions_help_description = {
    {config_setCertsPath, 
        "setCertsPath JSON_ARRAY\n"
        "\tjson format - [certsPath]\n"
        "\t\tcertsPath [STRING] - filesystem's path to certs file"
    },
    {core_waitEvent, 
        "waitEvent JSON_ARRAY\n"
        "\tjson format - []\n"
        "\talways run in new thread (works only in -i mode)"
    },
    {core_getEvent, 
        "getEvent JSON_ARRAY\n"
        "\tjson format - []"
    },
    {core_emitBreakEvent, 
        "emitBreakEvent JSON_ARRAY\n"
        "\tjson format - []"
    },
    {core_connect, 
        "connect JSON_ARRAY\n"
        "\tjson format - [userPrivKey, solutionId, platformUrl]\n"
        "\t\tuserPrivKey [STRING] - user's private key in WIF format\n"
        "\t\tsolutionId [STRING] - ID of the Solution\n"
        "\t\tplatformUrl [STRING] - Platform's Endpoint URL"
    },
    {core_connectPublic, 
        "connectPublic JSON_ARRAY\n"
        "\tjson format - [solutionId, platformUrl]\n"
        "\t\tsolutionId [STRING] - ID of the Solution\n"
        "\t\tplatformUrl [STRING] - Platform's Endpoint URL"
    },
    {core_disconnect, 
        "platformDisconnect JSON_ARRAY\n"
        "\tjson format - []"
    },
    {core_getConnectionId, 
        "platformDisconnect JSON_ARRAY\n"
        "\tjson format - []"
    },
    {core_listContexts, 
        "listContexts JSON_ARRAY\n"
        "\tjson format - [pagingQuery:{skip, limit, sortOrder, lastId?}]\n"
        "\t\tpagingQuery [OBJECT] - list query parameters\n"
        "\t\t\tskip [NUMBER] - number of elements to skip from result\n"
        "\t\t\tlimit [NUMBER] - limit of elements to return for query\n"
        "\t\t\tsortOrder [NUMBER] - order of elements in result (\"asc\" for ascending, \"desc\" for descending)\n"
        "\t\t\tlastId [STRING] - ID of the element from which query results should start"
    },
    {core_backendRequest, 
        "backendRequest JSON_ARRAY\n"
        "\tjson format - [serverUrl, accessToken, method, paramsAsJson]\n"
        "\t\tserverUrl [STRING] - PrivMX Bridge server URL\n"
        "\t\taccessToken [STRING] - token for authorization (see PrivMX Bridge API for more details)\n"
        "\t\tmethod [STRING] - API method to call\n"
        "\t\tparamsAsJson [STRING] - API method's parameters in JSON format\n"
        "\tjson format - [serverUrl, method, paramsAsJson]\n"
        "\t\tserverUrl [STRING] - PrivMX Bridge server URL\n"
        "\t\tmethod [STRING] - API method to call\n"
        "\t\tparamsAsJson [STRING] - API method's parameters in JSON format\n"
        "\tjson format - [serverUrl, apiKeyId, apiKeySecret, mode, method, paramsAsJson]\n"
        "\t\tserverUrl [STRING] - PrivMX Bridge server URL\n"
        "\t\tapiKeyId [STRING] - API KEY ID (see PrivMX Bridge API for more details)\n"
        "\t\tapiKeySecret [STRING] - API KEY SECRET (see PrivMX Bridge API for more details)\n"
        "\t\tmode [NUMBER] - allows you to set whether the request should be signed (mode = 1) or plain (mode = 0)\n"
        "\t\tmethod [STRING] - API method to call\n"
        "\t\tparamsAsJson [STRING] - API method's parameters in JSON format"
    },
    {crypto_signData, 
        "signData JSON_ARRAY\n"
        "\tjson format - [data, privateKey]\n"
        "\t\tdata [BUFFER] - buffer to sign\n"
        "\t\tprivateKey  [STRING] - key used to sign data in WIF format"
    },
    {crypto_verifySignature, 
        "verifySignature JSON_ARRAY\n"
        "\tjson format - [data, signature, publicKey]\n"
        "\t\tdata [BUFFER] - buffer\n"
        "\t\tsignature [BUFFER] - signature of data to verify\n"
        "\t\tpublicKey [STRING] - public ECC key in BASE58DER format used to validate data"
    },
    {crypto_generatePrivateKey, 
        "generatePrivateKey JSON_ARRAY\n"
        "\tjson format - [randomSeed?]\n"
        "\t\trandomSeed [STRING] - string used as the base to generate the new key"
    },
    {crypto_derivePrivateKey, 
        "derivePrivateKey JSON_ARRAY\n"
        "\tjson format - [password, salt]\n"
        "\t\tpassword [STRING] - the password used to generate the new key\n"
        "\t\tsalt [STRING] - random string (additional input for the hashing function)"
    },
    {crypto_derivePublicKey, 
        "derivePublicKey JSON_ARRAY\n"
        "\tjson format - [privatekey]\n"
        "\t\tprivatekey [STRING] - private ECC key in WIF format"
    },
    {crypto_generateKeySymmetric, 
        "generateKeySymmetric JSON_ARRAY\n"
        "\tjson format - []"
    },
    {crypto_encryptDataSymmetric, 
        "encryptDataSymmetric JSON_ARRAY\n"
        "\tjson format - [data, symmetricKey]\n"
        "\t\tdata [BUFFER] - buffer to encrypt\n"
        "\t\tsymmetricKey [STRING] - key used to encrypt data"
    },
    {crypto_decryptDataSymmetric,
        "decryptDataSymmetric JSON_ARRAY\n"
        "\tjson format - [data, symmetricKey]\n"
        "\t\tdata [BUFFER] - buffer to decrypt\n"
        "\t\tsymmetricKey [STRING] - key used to decrypt data"
    },
    {crypto_convertPEMKeytoWIFKey, 
        "convertPEMKeytoWIFKey JSON_ARRAY\n"
        "\tjson format - [pemKey]\n"
        "\t\tpemKey [STRING] - private key to convert"
    },
    {thread_createThread, 
        "createThread JSON_ARRAY\n"
        "\tjson format - [contextId, users:[{userId, pubKey}], managers:[{userId, pubKey}], publicMeta, privateMeta]\n"
        "\t\tcontextId [STRING] - ID of the Context to create the Thread in\n"
        "\t\tusers [ARRAY] - vector of UserWithPubKey structs which indicates who will have access to the created Thread\n"
        "\t\t\tuserId [STRING] - ID of the user\n"
        "\t\t\tpubKey [STRING] - user's public key\n"
        "\t\tmanagers [STRING] - vector of UserWithPubKey structs which indicates who will have access (and management rights) to the created Thread\n"
        "\t\t\tuserId [STRING] - ID of the user\n"
        "\t\t\tpubKey [STRING] - user's public key\n"
        "\t\tpublicMeta [BUFFER] - public (unencrypted) metadata\n"
        "\t\tprivateMeta [BUFFER] - private (encrypted) metadata"
    },
    {thread_updateThread, 
        "updateThread JSON_ARRAY\n"
        "\tjson format - [threadId, users:[{userId, pubKey}], managers:[{userId, pubKey}], publicMeta, privateMeta, version, force, generateNewKey]\n"
        "\t\threadId [STRING] - ID of the Thread to update\n"
        "\t\tusers [ARRAY] - vector of UserWithPubKey which indicates who will have access to the updated Thread\n"
        "\t\t\tuserId [STRING] - ID of the user\n"
        "\t\t\tpubKey [STRING] - user's public key\n"
        "\t\tmanagers [ARRAY] - vector of UserWithPubKey which indicates who will have access (and management rights) to the updated Thread\n"
        "\t\t\tuserId [STRING] - ID of the user\n"
        "\t\t\tpubKey [STRING] - user's public key\n"
        "\t\tpublicMeta [BUFFER] - public (unencrypted) metadata\n"
        "\t\tprivateMeta [BUFFER] - private (encrypted) metadata\n"
        "\t\tversion [NUMBER] - current version of the updated Thread\n"
        "\t\tforce [BOOL] - force update (without checking version)\n"
        "\t\tforceGenerateNewKey [BOOL] - force to regenerate a key for the Thread"
        },
    {thread_getThread, 
        "getThread JSON_ARRAY\n"
        "\tjson format - [threadId]\n"
        "\t\tthreadId [STRING] - ID of Thread to get"
    },
    {thread_listThreads, 
        "listThreads JSON_ARRAY\n"
        "\tjson format - [contextId, pagingQuery:{skip, limit, sortOrder, lastId?}]\n"
        "\t\tcontextId [STRING] - ID of the Context to get the Threads from\n"
        "\t\tpagingQuery [OBJECT] - list query parameters\n"
        "\t\t\tskip [NUMBER] - number of elements to skip from result\n"
        "\t\t\tlimit [NUMBER] - limit of elements to return for query\n"
        "\t\t\tsortOrder [NUMBER] - order of elements in result (\"asc\" for ascending, \"desc\" for descending)\n"
        "\t\t\tlastId [STRING] - ID of the element from which query results should start"
    },
    {thread_deleteThread, 
        "deleteThread JSON_ARRAY\n"
        "\tjson format - [threadId]\n"
        "\t\tthreadId [STRING] - ID of the Thread to delete"
    },
    {thread_sendMessage, 
        "sendMessage JSON_ARRAY\n"
        "\tjson format - [threadId, publicMeta, privateMeta, data]\n"
        "\t\tthreadId [STRING] - ID of the Thread to send message to\n"
        "\t\tpublicMeta [BUFFER] - public message metadata\n"
        "\t\tprivateMeta [BUFFER] - private message metadata\n"
        "\t\tprivateMeta [BUFFER] - content of the message"
    },
    {thread_updateMessage, 
        "updateMessage JSON_ARRAY\n"
        "\tjson format - [messageId, publicMeta, privateMeta, data]\n"
        "\t\tmessageId [STRING] - ID of the message to update\n"
        "\t\tpublicMeta [BUFFER] - public message metadata\n"
        "\t\tprivateMeta [BUFFER] - private message metadata\n"
        "\t\tprivateMeta [BUFFER] - content of the message"
    },
    {thread_getMessage, 
        "getMessage JSON_ARRAY\n"
        "\tjson format - [messageId]\n"
        "\t\tmessageId [STRING] - ID of the message to get"
    },
    {thread_listMessages, 
        "listMessages JSON_ARRAY\n"
        "\tjson format - [threadId, pagingQuery:{skip, limit, sortOrder, lastId?}]\n"
        "\t\tthreadId [STRING] - ID of the Thread to list messages from\n"
        "\t\tpagingQuery [OBJECT] - list query parameters\n"
        "\t\t\tskip [NUMBER] - number of elements to skip from result\n"
        "\t\t\tlimit [NUMBER] - limit of elements to return for query\n"
        "\t\t\tsortOrder [NUMBER] - order of elements in result (\"asc\" for ascending, \"desc\" for descending)\n"
        "\t\t\tlastId [STRING] - ID of the element from which query results should start"
    },
    {thread_deleteMessage, 
        "deleteMessage JSON_ARRAY\n"
        "\tjson format - [messageId]\n"
        "\t\tmessageId [STRING] - ID of the message to delete"
    },
    {thread_subscribeForThreadEvents, 
        "subscribeForThreadEvents JSON_ARRAY\n"
        "\tjson format - []"
    },
    {thread_unsubscribeFromThreadEvents, 
        "unsubscribeFromThreadEvents JSON_ARRAY\n"
        "\tjson format - []"
    },
    {thread_subscribeForMessageEvents, 
        "subscribeForMessageEvents JSON_ARRAY\n"
        "\tjson format - [threadId]\n"
        "\t\tthreadId [STRING] - ID of the Thread to subscribe"
    },
    {thread_unsubscribeFromMessageEvents, 
        "unsubscribeFromMessageEvents JSON_ARRAY\n"
        "\tjson format - [threadId]\n"
        "\t\tthreadId [STRING] - ID of the Thread to unsubscribe"
    },
    {store_createStore, 
        "createStore JSON_ARRAY\n"
        "\tjson format - [contextId, users:[{userId, pubKey}], managers:[{userId, pubKey}], publicMeta, privateMeta]\n"
        "\t\tcontextId [STRING] - ID of the Context to create the Store in\n"
        "\t\tusers [ARRAY] - vector of UserWithPubKey structs which indicates who will have access to the created Store\n"
        "\t\t\tuserId [STRING] - ID of the user\n"
        "\t\t\tpubKey [STRING] - user's public key\n"
        "\t\tmanagers [STRING] - vector of UserWithPubKey structs which indicates who will have access (and management rights) to the created Store\n"
        "\t\t\tuserId [STRING] - ID of the user\n"
        "\t\t\tpubKey [STRING] - user's public key\n"
        "\t\tpublicMeta [BUFFER] - public (unencrypted) metadata\n"
        "\t\tprivateMeta [BUFFER] - private (encrypted) metadata"
    },
    {store_updateStore, 
        "updateStore JSON_ARRAY\n"
        "\tjson format - [storeId, users:[{userId, pubKey}], managers:[{userId, pubKey}], publicMeta, privateMeta, version, force, generateNewKey]\n"
        "\t\tstoreId [STRING] - ID of the Store to update\n"
        "\t\tusers [ARRAY] - vector of UserWithPubKey structs which indicates who will have access to the updated Store\n"
        "\t\t\tuserId [STRING] - ID of the user\n"
        "\t\t\tpubKey [STRING] - user's public key\n"
        "\t\tmanagers [STRING] - vector of UserWithPubKey structs which indicates who will have access (and management rights) to the updated Store\n"
        "\t\t\tuserId [STRING] - ID of the user\n"
        "\t\t\tpubKey [STRING] - user's public key\n"
        "\t\tpublicMeta [BUFFER] - public (unencrypted) metadata\n"
        "\t\tprivateMeta [BUFFER] - private (encrypted) metadata\n"
        "\t\tversion [NUMBER] - current version of the updated Store\n"
        "\t\tforce [BOOL] - force update (without checking version)\n"
        "\t\tforceGenerateNewKey [BOOL] - force to regenerate a key for the Store"
    },
    {store_getStore, 
        "getStore JSON_ARRAY\n"
        "\tjson format - [storeId]\n"
        "\t\tstoreId [STRING] - ID of the Store to get"
    },
    {store_listStores, 
        "listStores JSON_ARRAY\n"
        "\tjson format - [contextId, pagingQuery:{skip, limit, sortOrder, lastId?}]\n"
        "\t\tcontextId [STRING] - ID of the Context to get the Stores from\n"
        "\t\tpagingQuery [OBJECT] - list query parameters\n"
        "\t\t\tskip [NUMBER] - number of elements to skip from result\n"
        "\t\t\tlimit [NUMBER] - limit of elements to return for query\n"
        "\t\t\tsortOrder [NUMBER] - order of elements in result (\"asc\" for ascending, \"desc\" for descending)\n"
        "\t\t\tlastId [STRING] - ID of the element from which query results should start"
    },
    {store_deleteStore, 
        "deleteStore JSON_ARRAY\n"
        "\tjson format - [storeId]\n"
        "\t\tstoreId [STRING] - ID of the Store to delete"
    },
    {store_createFile, 
        "createFile JSON_ARRAY\n"
        "\tjson format - [storeId, publicMeta, privateMeta, size]\n"
        "\t\tstoreId [STRING] - ID of the Store to create the file in\n"
        "\t\tpublicMeta [BUFFER] - public file metadata\n"
        "\t\tprivateMeta [BUFFER] - private file metadata\n"
        "\t\tsize [NUMBER] - size of the file"
    },
    {store_updateFile, 
        "updateFile JSON_ARRAY\n"
        "\tjson format - [fileId, publicMeta, privateMeta, size]\n"
        "\t\tfileId [STRING] - ID of the file to update\n"
        "\t\tpublicMeta [BUFFER] - public file metadata\n"
        "\t\tprivateMeta [BUFFER] - private file metadata\n"
        "\t\tsize [NUMBER] - size of the file"
    },
    {store_updateFileMeta, 
        "updateFileMeta JSON_ARRAY\n"
        "\tjson format - [fileId, publicMeta, privateMeta]\n"
        "\t\tfileId [STRING] - ID of the file to update\n"
        "\t\tpublicMeta [BUFFER] - public file metadata\n"
        "\t\tprivateMeta [BUFFER] - private file metadata"
    },
    {store_getFile, 
        "getFile JSON_ARRAY\n"
        "\tjson format - [fileId]\n"
        "\t\tfileId [STRING] - ID of the file to get"
    },
    {store_listFiles, 
        "listFiles JSON_ARRAY\n"
        "\tjson format - [storeId, pagingQuery:{skip, limit, sortOrder, lastId?}]\n"
        "\t\tstoreId [STRING] - ID of the Store to get files from\n"
        "\t\tpagingQuery [OBJECT] - list query parameters\n"
        "\t\t\tskip [NUMBER] - number of elements to skip from result\n"
        "\t\t\tlimit [NUMBER] - limit of elements to return for query\n"
        "\t\t\tsortOrder [NUMBER] - order of elements in result (\"asc\" for ascending, \"desc\" for descending)\n"
        "\t\t\tlastId [STRING] - ID of the element from which query results should start"
    },
    {store_deleteFile, 
        "deleteFile JSON_ARRAY\n"
        "\tjson format - [fileId]\n"
        "\t\tfileId [STRING] - ID of the file to delete"
    },
    {store_openFile, 
        "openFile JSON_ARRAY\n"
        "\tjson format - [fileId]\n"
        "\t\tfileId [STRING] - ID of the file to read"
    },
    {store_readFromFile, 
        "readFromFile JSON_ARRAY\n"
        "\tjson format - [fileHandle, length]\n"
        "\t\tfileHandle [NUMBER] - handle to read file data\n"
        "\t\tlength [NUMBER] - size of data to read"
    },
    {store_writeToFile, 
        "writeToFile JSON_ARRAY\n"
        "\tjson format - [fileHandle, dataChunk]\n"
        "\t\tfileHandle [NUMBER] - handle to write file data\n"
        "\t\tdataChunk [BUFFER] - file data chunk"
    },
    {store_seekInFile, 
        "seekInFile JSON_ARRAY\n"
        "\tjson format - [fileHandle, position]\n"
        "\t\tfileHandle [NUMBER] - handle to read file data\n"
        "\t\tposition [NUMBER] - new cursor position"
    },
    {store_closeFile, 
        "closeFile JSON_ARRAY\n"
        "\tjson format - [fileHandle]\n"
        "\t\tfileHandle [NUMBER] - handle to read/write file data"
    },
    {store_subscribeForStoreEvents, 
        "subscribeForStoreEvents JSON_ARRAY\n"
        "\tjson format - []"
    },
    {store_unsubscribeFromStoreEvents, 
        "unsubscribeFromStoreEvents JSON_ARRAY\n"
        "\tjson format - []"
    },
    {store_subscribeForFileEvents, 
        "subscribeForFileEvents JSON_ARRAY\n"
        "\tjson format - [storeId]\n"
        "\t\tstoreId [STRING] - ID of the Store to subscribe"
    },
    {store_unsubscribeFromFileEvents, 
        "unsubscribeFromFileEvents JSON_ARRAY\n"
        "\tjson format - [storeId]\n"
        "\t\tstoreId [STRING] - ID of the Store to unsubscribe"
    },
    {inbox_createInbox, 
        "createInbox JSON_ARRAY\n"
        "\tjson format - [contextId, users:[{userId, pubKey}], managers:[{userId, pubKey}], publicMeta, privateMeta, filesConfig?:{minCount, maxCount, maxFileSize, maxWholeUploadSize}]\n"
        "\t\tcontextId [STRING] - ID of the Context of the new Inbox\n"
        "\t\tusers [ARRAY] -  vector of UserWithPubKey which indicates who will have access to the created Inbox\n"
        "\t\t\tuserId [STRING] - ID of the user\n"
        "\t\t\tpubKey [STRING] - user's public key\n"
        "\t\tmanagers [ARRAY] -  vector of UserWithPubKey which indicates who will have access (and management rights) to the created Inbox\n"
        "\t\t\tuserId [STRING] - ID of the user\n"
        "\t\t\tpubKey [STRING] - user's public key\n"
        "\t\tpublicMeta [BUFFER] - public (unencrypted) metadata\n"
        "\t\tprivateMeta [BUFFER] - private (encrypted) metadata\n"
        "\t\tfilesConfig [OBJECT] - to override default file configuration\n"
        "\t\t\tminCount [NUMBER] - minimum numer of files required when sending inbox entry\n"
        "\t\t\tmaxCount [NUMBER] - maximum numer of files allowed when sending inbox entry\n"
        "\t\t\tmaxFileSize [NUMBER] - maximum file size allowed when sending inbox entry\n"
        "\t\t\tmaxWholeUploadSize [NUMBER] - maximum size of all files in total allowed when sending inbox entry"
    },
    {inbox_updateInbox, 
        "updateInbox JSON_ARRAY\n"
        "\tjson format - [inboxId, users:[{userId, pubKey}], managers:[{userId, pubKey}], publicMeta, privateMeta, filesConfig?:{minCount, maxCount, maxFileSize, maxWholeUploadSize}, version, force, forceGenerateNewKey]\n"
        "\t\tinboxId [STRING] - ID of the Inbox to update\n"
        "\t\tusers [ARRAY] -  vector of UserWithPubKey which indicates who will have access to the updated Inbox\n"
        "\t\t\tuserId [STRING] - ID of the user\n"
        "\t\t\tpubKey [STRING] - user's public key\n"
        "\t\tmanagers [ARRAY] -  vector of UserWithPubKey which indicates who will have access (and management rights) to the updated Inbox\n"
        "\t\t\tuserId [STRING] - ID of the user\n"
        "\t\t\tpubKey [STRING] - user's public key\n"
        "\t\tpublicMeta [BUFFER] - public (unencrypted) metadata\n"
        "\t\tprivateMeta [BUFFER] - private (encrypted) metadata\n"
        "\t\tfilesConfig [OBJECT] - to override default file configuration\n"
        "\t\t\tminCount [NUMBER] - minimum numer of files required when sending inbox entry\n"
        "\t\t\tmaxCount [NUMBER] - maximum numer of files allowed when sending inbox entry\n"
        "\t\t\tmaxFileSize [NUMBER] - maximum file size allowed when sending inbox entry\n"
        "\t\t\tmaxWholeUploadSize [NUMBER] - maximum size of all files in total allowed when sending inbox entry\n"
        "\t\tversion [NUMBER] - current version of the updated Inbox\n"
        "\t\tforce [BOOL] - force update (without checking version)\n"
        "\t\tforceGenerateNewKey [BOOL] - force to regenerate a key for the Inbox"
    },
    {inbox_getInbox, 
        "getInbox JSON_ARRAY\n"
        "\tjson format - [inboxId]\n"
        "\t\tinboxId [STRING] - ID of the Inbox to get"
    },
    {inbox_listInboxes, 
        "listInboxes JSON_ARRAY\n"
        "\tjson format - [contextId, pagingQuery:{skip, limit, sortOrder, lastId?}]\n"
        "\t\tcontextId [STRING] - ID of the Context to get the Inboxes from\n"
        "\t\tpagingQuery [OBJECT] - list query parameters\n"
        "\t\t\tskip [NUMBER] - number of elements to skip from result\n"
        "\t\t\tlimit [NUMBER] - limit of elements to return for query\n"
        "\t\t\tsortOrder [NUMBER] - order of elements in result (\"asc\" for ascending, \"desc\" for descending)\n"
        "\t\t\tlastId [STRING] - ID of the element from which query results should start"
    },
    {inbox_deleteInbox, 
        "deleteInbox JSON_ARRAY\n"
        "\tjson format - [inboxId]\n"
        "\t\tinboxId [STRING] - ID of the Inbox to delete"
    },
    {inbox_getInboxPublicView, 
        "getInboxPublicView JSON_ARRAY\n"
        "\tjson format - [inboxId]\n"
        "\t\tinboxId [STRING] - ID of the Inbox to get"
    },
    {inbox_prepareEntry, 
        "prepareEntry JSON_ARRAY\n"
        "\tjson format - [inboxId, data, inboxFileHandles:[fileHandle], userPrivKey?]\n"
        "\t\tinboxId [STRING] - ID of the Inbox to which the request applies\n"
        "\t\tdata [BUFFER] - entry data to send\n"
        "\t\tinboxFileHandles [ARRAY] - list of file handles that will be sent with the request\n"
        "\t\t\tfileHandle [NUMBER] - write handle to the file\n"
        "\t\tuserPrivKey [STRING] - sender's private key which can be used later to encrypt data for that sender"
    },
    {inbox_sendEntry, 
        "sendEntry JSON_ARRAY\n"
        "\tjson format - [inboxHandle]\n"
        "\t\tinboxHandle [NUMBER] - ID of the Inbox to which the request applies"
    },
    {inbox_readEntry, 
        "readEntry JSON_ARRAY\n"
        "\tjson format - [entryId]\n"
        "\t\tentryId [STRING] - ID of an entry to read from the Inbox"
    },
    {inbox_listEntries, 
        "listEntries JSON_ARRAY\n"
        "\tjson format - [inboxId, pagingQuery:{skip, limit, sortOrder, lastId?}]\n"
        "\t\tinboxId [STRING] - ID of the Inbox\n"
        "\t\tpagingQuery [OBJECT] - list query parameters\n"
        "\t\t\tskip [NUMBER] - number of elements to skip from result\n"
        "\t\t\tlimit [NUMBER] - limit of elements to return for query\n"
        "\t\t\tsortOrder [NUMBER] - order of elements in result (\"asc\" for ascending, \"desc\" for descending)\n"
        "\t\t\tlastId [STRING] - ID of the element from which query results should start"
    },
    {inbox_deleteEntry, 
        "deleteEntry JSON_ARRAY\n"
        "\tjson format - [entryId]\n"
        "\t\tentryId [STRING] - ID of an entry to delete"
    },
    {inbox_createFileHandle, 
        "createFileHandle JSON_ARRAY\n"
        "\tjson format - [publicMeta, privateMeta, fileSize]\n"
        "\t\tpublicMeta [BUFFER] - file's public metadata\n"
        "\t\tprivateMeta [BUFFER] - file's private metadata\n"
        "\t\tfileSize [NUMBER] - size of the file to send"
    },
    {inbox_writeToFile, 
        "writeToFile JSON_ARRAY\n"
        "\tjson format - [inboxHandle, fileHandle, dataChunk]\n"
        "\t\tinboxHandle [NUMBER] - ID of the Inbox to which the request applies\n"
        "\t\tfileHandle [NUMBER] - handle to the file where the uploaded chunk belongs\n"
        "\t\tdataChunk [BUFFER] - dataChunk - file chunk to send"
    },
    {inbox_openFile,
        "openFile JSON_ARRAY\n"
        "\tjson format - [fileId]\n"
        "\t\tfileId [STRING] - ID of the file to read"
    },
    {inbox_readFromFile, 
        "readFromFile JSON_ARRAY\n"
        "\tjson format - [fileHandle, length]\n"
        "\t\tfileHandle [NUMBER] - handle to the file\n"
        "\t\tlength [NUMBER] - size of data to read"
    },
    {inbox_seekInFile, 
        "seekInFile JSON_ARRAY\n"
        "\tjson format - [fileHandle, position]\n"
        "\t\tfileHandle [NUMBER] - handle to the file\n"
        "\t\tposition [NUMBER] - sets new cursor position"
    },
    {inbox_closeFile, 
        "closeFile JSON_ARRAY\n"
        "\tjson format - [fileHandle]\n"
        "\t\tfileHandle [NUMBER] - handle to the file"
    },
    {inbox_subscribeForInboxEvents, 
        "subscribeForInboxEvents JSON_ARRAY\n"
        "\tjson format - []"
    },
    {inbox_unsubscribeFromInboxEvents, 
        "unsubscribeFromInboxEvents JSON_ARRAY\n"
        "\tjson format - []"
    },
    {inbox_subscribeForEntryEvents, 
        "subscribeForEntryEvents JSON_ARRAY\n"
        "\tjson format - [inboxId]\n"
        "\t\tinboxId [STRING] - ID of the Inbox to subscribe"
    },
    {inbox_unsubscribeFromEntryEvents, 
        "unsubscribeFromEntryEvents JSON_ARRAY\n"
        "\tjson format - [inboxId]\n"
        "\t\tinboxId [STRING] - ID of the Inbox to unsubscribe"
    },
};

inline const std::unordered_map<func_enum, std::string> functions_help_short_description = {
    {config_setCertsPath, "Allows to set path to the SSL certificate file."},
    {core_waitEvent, "Starts a loop waiting for an Event. Runs in new thread"},
    {core_getEvent, "Gets the first event from the events queue."},
    {core_emitBreakEvent, "Puts the break event on the events queue."},
    {core_connect, "Connects to the Platform backend."},
    {core_connectPublic, "Connects to the Platform backend as a guest user."},
    {core_disconnect, "Disconnects from the Platform backend."},
    {core_getConnectionId, "Gets the ID of the current connection."},
    {core_listContexts, "Gets a list of Contexts available for the user."},
    {core_backendRequest, "Sends request to PrivMX Bridge API."},
    {crypto_signData, "Creates a signature of data using given key."},
    {crypto_verifySignature, "Validate a signature of data using given key."},
    {crypto_generatePrivateKey, "Generates a new private ECC key."},
    {crypto_derivePrivateKey, "Generates a new private ECC key from a password using pbkdf2."},
    {crypto_derivePublicKey, "Generates a new public ECC key as a pair for an existing private key."},
    {crypto_generateKeySymmetric, "Generates a new symmetric key."},
    {crypto_encryptDataSymmetric, "Encrypts buffer with a given key using AES."},
    {crypto_decryptDataSymmetric, "Decrypts buffer with a given key using AES."},
    {crypto_convertPEMKeytoWIFKey, "Converts given private key in PEM format to its WIF format."},
    {thread_createThread, "Creates a new Thread in given Context."},
    {thread_updateThread, "Updates an existing Thread."},
    {thread_getThread, "Gets a Thread by given Thread ID."},
    {thread_listThreads, "Gets a list of Threads in given Context."},
    {thread_deleteThread, "Deletes a Thread by given Thread ID."},
    {thread_sendMessage, "Sends a message in a Thread."},
    {thread_updateMessage, "Update message in a Thread."},
    {thread_getMessage, "Gets a message by given message ID."},
    {thread_listMessages, "Gets a list of messages from a Thread."},
    {thread_deleteMessage, "Deletes a message by given message ID."},
    {thread_subscribeForThreadEvents, "Subscribes for the Thread module main events."},
    {thread_unsubscribeFromThreadEvents, "Unsubscribes from the Thread module main events."},
    {thread_subscribeForMessageEvents, "Subscribes for events in given Thread."},
    {thread_unsubscribeFromMessageEvents, "Unsubscribes from events in given Thread."},
    {store_createStore, "Creates a new Store in given Context."},
    {store_updateStore, "Updates an existing Store."},
    {store_getStore, "Gets a single Store by given Store ID."},
    {store_listStores, "Gets a list of Stores in given Context."},
    {store_deleteStore, "Deletes a Store by given Store ID."},
    {store_createFile, "Creates a new file in a Store."},
    {store_updateFile, "Update an existing file in a Store."},
    {store_updateFileMeta, "Update metadata of an existing file in a Store."},
    {store_getFile, "Gets a single file by the given file ID."},
    {store_listFiles, "Gets a list of files in given Store."},
    {store_deleteFile, "Deletes a file by given ID."},
    {store_openFile, "Opens a file to read."},
    {store_readFromFile, "Reads file data."},
    {store_writeToFile, "Writes a file data."},
    {store_seekInFile, "Moves read cursor."},
    {store_closeFile, "Closes the file handle."},
    {store_subscribeForStoreEvents, "Subscribes for the Store module main events."},
    {store_unsubscribeFromStoreEvents, "Unsubscribes from the Store module main events."},
    {store_subscribeForFileEvents, "Subscribes for events in given Store."},
    {store_unsubscribeFromFileEvents, "Unsubscribes from events in given Store."},
    {inbox_createInbox, "Creates a new Inbox."},
    {inbox_updateInbox, "Updates an existing Inbox."},
    {inbox_getInbox, "Gets a single Inbox by given Inbox ID."},
    {inbox_listInboxes, "Gets s list of Inboxes in given Context."},
    {inbox_deleteInbox, "Deletes an Inbox by given Inbox ID."},
    {inbox_getInboxPublicView, "Gets public data of given Inbox."},
    {inbox_prepareEntry, "Prepares a request to send data to an Inbox."},
    {inbox_sendEntry, "Sends data to an Inbox."},
    {inbox_readEntry, "Gets an entry from an Inbox."},
    {inbox_listEntries, "Gets list of entries in given Inbox."},
    {inbox_deleteEntry, "Delete an entry from an Inbox."},
    {inbox_createFileHandle, "Creates a file handle to send a file to an Inbox."},
    {inbox_writeToFile, "Sends file's data chunk to an Inbox."},
    {inbox_openFile, "Opens a file to read."},
    {inbox_readFromFile, "Reads file data."},
    {inbox_seekInFile, "Moves file's read cursor."},
    {inbox_closeFile, "Closes a file by given handle."},
    {inbox_subscribeForInboxEvents, "Subscribes for the Inbox module main events."},
    {inbox_unsubscribeFromInboxEvents, "Unsubscribes from the Inbox module main events."},
    {inbox_subscribeForEntryEvents, "Subscribes for events in given Inbox."},
    {inbox_unsubscribeFromEntryEvents, "Unsubscribes from events in given Inbox."},
};


inline const std::unordered_map<func_enum, std::string> functions_action_description = {
    {config_setCertsPath, "Setting CertsPath"},
    {core_waitEvent, "Waiting for event"},
    {core_getEvent, "Getting event"},
    {core_emitBreakEvent, "Emitting break event"},
    {core_connect, "Connecting"},
    {core_connectPublic, "Connecting public"},
    {core_disconnect, "Disconnecting"},
    {core_getConnectionId, "Getting connection id"},
    {core_listContexts, "Getting contexts"},
    {core_backendRequest, "Running backendRequest"},
    {crypto_signData, "Signing data"},
    {crypto_verifySignature, "Verifying signature"},
    {crypto_generatePrivateKey, "Generating private key"},
    {crypto_derivePrivateKey, "Deriving private key"},
    {crypto_derivePublicKey, "Deriving public key"},
    {crypto_generateKeySymmetric, "Generating symmetric key"},
    {crypto_encryptDataSymmetric, "Encrypt data using symmetric key"},
    {crypto_decryptDataSymmetric, "Decrypting data using symmetric key"},
    {crypto_convertPEMKeytoWIFKey, "Convert PEM key to WIF key"},
    {thread_createThread, "Creating thread"},
    {thread_updateThread, "Updating thread"},
    {thread_getThread, "Getting thread"},
    {thread_listThreads, "Getting threads"},
    {thread_deleteThread, "Deleting thread"},
    {thread_subscribeForThreadEvents, "Subscribing for thread events"},
    {thread_unsubscribeFromThreadEvents, "Unsubscribing from thread events"},
    {thread_subscribeForMessageEvents, "Subscribing for message events"},
    {thread_unsubscribeFromMessageEvents, "Unsubscribing from message events"},
    {store_createStore, "Creating store"},
    {store_updateStore, "Updating store"},
    {store_getStore, "Getting store"},
    {store_listStores, "Getting stores"},
    {store_deleteStore, "Deleting store"},
    {store_createFile, "Creating store file"},
    {store_updateFile, "Updating store file"},
    {store_updateFileMeta, "Updating store file meta"},
    {store_getFile, "Getting store file"},
    {store_listFiles, "Getting store files"},
    {store_deleteFile, "Deleting store file"},
    {store_openFile, "Opening store file"},
    {store_readFromFile, "Reading from store file"},
    {store_writeToFile, "Writing to store file"},
    {store_seekInFile, "Seeking in store file"},
    {store_closeFile, "Closing store file"},
    {store_subscribeForStoreEvents, "Subscribing for store events"},
    {store_unsubscribeFromStoreEvents, "Unsubscribing from store events"},
    {store_subscribeForFileEvents, "Subscribing for file events"},
    {store_unsubscribeFromFileEvents, "Unsubscribing from file events"},
    {inbox_createInbox, "Creating inbox"},
    {inbox_updateInbox, "Updating inbox"},
    {inbox_getInbox, "Getting inbox"},
    {inbox_listInboxes, "Getting inboxes"},
    {inbox_deleteInbox, "Deleting inbox"},
    {inbox_getInboxPublicView, "Getting inbox public view"},
    {inbox_prepareEntry, "Preparing entry"},
    {inbox_sendEntry, "Sending entry"},
    {inbox_readEntry, "Reading entry"},
    {inbox_listEntries, "Getting entries"},
    {inbox_deleteEntry, "Deleting entry"},
    {inbox_createFileHandle, "Creating file handle"},
    {inbox_writeToFile, "Writing to file"},
    {inbox_openFile, "Opening file"},
    {inbox_readFromFile, "Reading form file"},
    {inbox_seekInFile, "Seeking in file"},
    {inbox_closeFile, "Closing file"},
    {inbox_subscribeForInboxEvents, "Subscribing for inbox events"},
    {inbox_unsubscribeFromInboxEvents, "Unsubscribing from inbox events"},
    {inbox_subscribeForEntryEvents, "Subscribing for entry events"},
    {inbox_unsubscribeFromEntryEvents, "Unsubscribing from entry events"},
};

} // privmxcli
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_PRIVMXCLI_VARS_FUN_HELP_HPP_