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

#include <privmx/utils/JsonHelper.hpp>

namespace privmx {
namespace endpoint {
namespace thread {
namespace dynamic {

#define THREAD_DATA_V1_FIELDS(F)\
    F(title, std::string)\
    F(statusCode, int64_t)
JSON_STRUCT(ThreadDataV1, THREAD_DATA_V1_FIELDS);

#define MESSAGE_DATA_AUTHOR_FIELDS(F)\
    F(userId, std::string)\
    F(pubKey, std::string)
JSON_STRUCT(MessageDataAuthor, MESSAGE_DATA_AUTHOR_FIELDS);


#define MESSAGE_DATA_DESTINATION_FIELDS(F)\
    F(server, std::string)\
    F(contextId, std::string)\
    F(threadId, std::string)
JSON_STRUCT(MessageDataDestination, MESSAGE_DATA_DESTINATION_FIELDS);

#define I_MESSAGE_DATA_FIELDS(F)\
    F(v, int64_t)
JSON_STRUCT(IMessageData, I_MESSAGE_DATA_FIELDS);

#define I_MESSAGE_DATA_SIGNED_FIELDS(F)\
    F(data, IMessageData)\
    F(dataBuf, Pson::BinaryString)\
    F(dataSignature, Pson::BinaryString)
JSON_STRUCT(IMessageDataSigned, I_MESSAGE_DATA_SIGNED_FIELDS);

#define MESSAGE_DATA_V2_FIELDS(F)\
    F(msgId, std::string)\
    F(type, std::string)\
    F(text, std::string)\
    F(date, int64_t)\
    F(deleted, bool)\
    F(author, MessageDataAuthor)\
    F(destination, MessageDataDestination)\
    F(statusCode, int64_t)
JSON_STRUCT_EXT(MessageDataV2, IMessageData, MESSAGE_DATA_V2_FIELDS);

#define MESSAGE_DATA_V2_SIGNED_FIELDS(F)\
    F(data, MessageDataV2)
JSON_STRUCT_EXT(MessageDataV2Signed, IMessageDataSigned, MESSAGE_DATA_V2_SIGNED_FIELDS);

#define MESSAGE_DATA_V3_FIELDS(F)\
    F(publicMeta, Pson::BinaryString)\
    F(privateMeta, Pson::BinaryString)\
    F(data, Pson::BinaryString)\
    F(statusCode, int64_t)
JSON_STRUCT_EXT(MessageDataV3, IMessageData, MESSAGE_DATA_V3_FIELDS);
#define MESSAGE_DATA_V3_SIGNED_FIELDS(F)\
    F(data, MessageDataV3)
JSON_STRUCT_EXT(MessageDataV3Signed, IMessageDataSigned, MESSAGE_DATA_V3_SIGNED_FIELDS);


} // dynamic
} // thread
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_DYNAMICTYPES_HPP_
