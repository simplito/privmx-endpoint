/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_THREAD_DYNAMICTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_DYNAMICTYPES_HPP_

#include <string>

#include "privmx/endpoint/core/TypesMacros.hpp"

namespace privmx {
namespace endpoint {
namespace thread {
namespace dynamic {

ENDPOINT_CLIENT_TYPE(internalMeta)
    STRING_FIELD(threadCCN)
    INT64_FIELD(KeyId)
TYPE_END

ENDPOINT_CLIENT_TYPE(ThreadDataV1)
    STRING_FIELD(title)
    INT64_FIELD(statusCode)
TYPE_END

ENDPOINT_CLIENT_TYPE(MessageDataAuthor)
    STRING_FIELD(userId)
    STRING_FIELD(pubKey)
TYPE_END

ENDPOINT_CLIENT_TYPE(MessageDataDestination)
    STRING_FIELD(server)
    STRING_FIELD(contextId)
    STRING_FIELD(threadId)
TYPE_END

ENDPOINT_CLIENT_TYPE(IMessageData)
    INT64_FIELD(v)
TYPE_END

ENDPOINT_CLIENT_TYPE(IMessageDataSigned)
    OBJECT_FIELD(data, IMessageData)
    BINARYSTRING_FIELD(dataBuf)
    BINARYSTRING_FIELD(dataSignature)
TYPE_END

ENDPOINT_CLIENT_TYPE_INHERIT(MessageDataV2, IMessageData)
    STRING_FIELD(msgId)
    STRING_FIELD(type)
    STRING_FIELD(text)
    INT64_FIELD(date)
    BOOL_FIELD(deleted)
    OBJECT_FIELD(author, MessageDataAuthor)
    OBJECT_FIELD(destination, MessageDataDestination)
    INT64_FIELD(statusCode)
TYPE_END

ENDPOINT_CLIENT_TYPE_INHERIT(MessageDataV2Signed, IMessageDataSigned)
    OBJECT_FIELD(data, MessageDataV2)
TYPE_END

ENDPOINT_CLIENT_TYPE_INHERIT(MessageDataV3, IMessageData)
    BINARYSTRING_FIELD(publicMeta) 
    BINARYSTRING_FIELD(privateMeta)
    BINARYSTRING_FIELD(data)
    INT64_FIELD(statusCode)
TYPE_END

ENDPOINT_CLIENT_TYPE_INHERIT(MessageDataV3Signed, IMessageDataSigned)
    OBJECT_FIELD(data, MessageDataV3)
TYPE_END

ENDPOINT_CLIENT_TYPE(ThreadInternalMetaV5)
    STRING_FIELD(secret)
    STRING_FIELD(resourceId)
    STRING_FIELD(randomId)
TYPE_END


} // dynamic
} // thread
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_DYNAMICTYPES_HPP_
