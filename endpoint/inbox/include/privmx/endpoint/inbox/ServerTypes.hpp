/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_INBOX_SERVERTYPES2_0_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_SERVERTYPES2_0_HPP_

#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/endpoint/core/TypesMacros.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>


namespace privmx {
namespace endpoint {
namespace inbox {
namespace server {

    class KeyEntrySet : public utils::TypedObject
    {
    public:
        ENDPOINT_SERVER_TYPE_CONSTRUCTOR(KeyEntrySet)
        void initialize() override {
            initializeObject({"user", "keyId", "data"});
        }
        STRING_FIELD(user)
        STRING_FIELD(keyId)
        STRING_FIELD(data)
    };

    class FileConfig : public utils::TypedObject
    {
    public:
        ENDPOINT_SERVER_TYPE_CONSTRUCTOR(FileConfig)
        void initialize() override {
        }
        INT64_FIELD(minCount)
        INT64_FIELD(maxCount)
        INT64_FIELD(maxFileSize)
        INT64_FIELD(maxWholeUploadSize)
    };

    class InboxData : public utils::TypedObject
    {
    public:
        ENDPOINT_SERVER_TYPE_CONSTRUCTOR(InboxData)
        void initialize() override {
            INIT_OBJECT(fileConfig, FileConfig)
        }
        STRING_FIELD(threadId)
        STRING_FIELD(storeId)
        OBJECT_FIELD(fileConfig, FileConfig)
        VAR_FIELD(meta) // required by server ak privateData
        VAR_FIELD(publicData) // required by server ak publicData
    };

    class InboxDataEntry : public utils::TypedObject
    {
    public:
        ENDPOINT_SERVER_TYPE_CONSTRUCTOR(InboxDataEntry)
        void initialize() override {
            INIT_OBJECT(data, InboxData)
        }
        STRING_FIELD(keyId)
        OBJECT_FIELD(data, InboxData)
    };

    class Inbox : public utils::TypedObject
    {
    public:
        ENDPOINT_SERVER_TYPE_CONSTRUCTOR(Inbox)
        void initialize() override {
            INIT_LIST(data, InboxDataEntry)
            INIT_LIST(users, std::string)
            INIT_LIST(managers, std::string)
            INIT_LIST(keys, privmx::endpoint::core::types::KeyEntry)
        }
        STRING_FIELD(id)
        STRING_FIELD(contextId)
        INT64_FIELD(createDate)
        STRING_FIELD(creator)
        INT64_FIELD(lastModificationDate)
        STRING_FIELD(lastModifier)
        LIST_FIELD(data, InboxDataEntry)
        STRING_FIELD(keyId)
        LIST_FIELD(users, std::string)
        LIST_FIELD(managers, std::string)
        LIST_FIELD(keys, privmx::endpoint::core::server::KeyEntry)
        INT64_FIELD(version)
        VAR_FIELD(policy)
    };

    ENDPOINT_CLIENT_TYPE_INHERIT(PrivateDataV4, core::server::VersionedData)
        STRING_FIELD(privateMeta)
        STRING_FIELD(internalMeta)
        STRING_FIELD(authorPubKey)
    TYPE_END

    ENDPOINT_CLIENT_TYPE_INHERIT(PublicDataV4, core::server::VersionedData)
        STRING_FIELD(publicMeta)
        OBJECT_PTR_FIELD(publicMetaObject)
        STRING_FIELD(authorPubKey)
        STRING_FIELD(inboxPubKey)
        STRING_FIELD(inboxKeyId)
    TYPE_END

    ENDPOINT_CLIENT_TYPE_INHERIT(PrivateDataV5, core::server::VersionedData)
        STRING_FIELD(privateMeta)
        STRING_FIELD(internalMeta)
        STRING_FIELD(authorPubKey)
        STRING_FIELD(dio)
    TYPE_END

    ENDPOINT_CLIENT_TYPE_INHERIT(PublicDataV5, core::server::VersionedData)
        STRING_FIELD(publicMeta)
        OBJECT_PTR_FIELD(publicMetaObject)
        STRING_FIELD(authorPubKey)
        STRING_FIELD(inboxPubKey)
        STRING_FIELD(inboxKeyId)
    TYPE_END

    /////////////// MODELS AND RESULTS ////////////////////////////

    class InboxCreateModel : public utils::TypedObject
    {
    public:
        ENDPOINT_SERVER_TYPE_CONSTRUCTOR(InboxCreateModel)
        void initialize() override {
            INIT_LIST(users, std::string)
            INIT_LIST(managers, std::string)
            INIT_LIST(keys, privmx::endpoint::core::types::KeyEntrySet)
            INIT_OBJECT(data, InboxData)
        }
        STRING_FIELD(inboxId)
        STRING_FIELD(contextId)
        LIST_FIELD(users, std::string) //cloud userId
        LIST_FIELD(managers, std::string) //cloud userId
        OBJECT_FIELD(data, InboxData)
        STRING_FIELD(keyId)
        LIST_FIELD(keys, privmx::endpoint::core::server::KeyEntrySet)
        VAR_FIELD(policy)
    };

    class InboxCreateResult : public utils::TypedObject
    {
    public:
        ENDPOINT_SERVER_TYPE_CONSTRUCTOR(InboxCreateResult)
        void initialize() override {
            initializeObject({"inboxId"});
        }
        STRING_FIELD(inboxId)
    };

    class InboxUpdateModel : public utils::TypedObject
    {
    public:
        ENDPOINT_SERVER_TYPE_CONSTRUCTOR(InboxUpdateModel)
        void initialize() override {
            INIT_LIST(users, std::string)
            INIT_LIST(managers, std::string)
            INIT_LIST(keys, privmx::endpoint::core::server::KeyEntrySet)
            INIT_OBJECT(data, InboxData)
        }
        STRING_FIELD(id)
        LIST_FIELD(users, std::string) //cloud userId
        LIST_FIELD(managers, std::string) //cloud userId
        OBJECT_FIELD(data, InboxData)
        STRING_FIELD(keyId)
        LIST_FIELD(keys, privmx::endpoint::core::server::KeyEntrySet)
        INT64_FIELD(version)
        BOOL_FIELD(force)
        VAR_FIELD(policy)
    };

    class InboxGetModel : public utils::TypedObject
    {
    public:
        ENDPOINT_SERVER_TYPE_CONSTRUCTOR(InboxGetModel)
        void initialize() override {
            initializeObject({"id"});
        }
        STRING_FIELD(id)
        STRING_FIELD(type)
    };

    class InboxGetResult : public utils::TypedObject
    {
    public:
        ENDPOINT_SERVER_TYPE_CONSTRUCTOR(InboxGetResult)
        void initialize() override {
            INIT_OBJECT(inbox, Inbox)
        }
        OBJECT_FIELD(inbox, Inbox)
    };


    class InboxListModel : public core::server::ListModel
    {
    public:
        ENDPOINT_SERVER_TYPE_CONSTRUCTOR_INHERIT(InboxListModel, core::server::ListModel)
        void initialize() override {
        }
        STRING_FIELD(contextId)
    };

    class InboxListResult : public utils::TypedObject
    {
    public:
        ENDPOINT_SERVER_TYPE_CONSTRUCTOR(InboxListResult)
        void initialize() override {
            initializeObject({"count"});
            INIT_LIST(inboxes, Inbox)
        }
        LIST_FIELD(inboxes, Inbox)
        INT64_FIELD(count)
    };

    class InboxFile : public utils::TypedObject
    {
    public:
        ENDPOINT_SERVER_TYPE_CONSTRUCTOR(InboxFile)
        void initialize() override {}
        INT64_FIELD(fileIndex)
        INT64_FIELD(thumbIndex)
        VAR_FIELD(meta)
    };

    class InboxSendModel : public utils::TypedObject
    {
    public:
        ENDPOINT_SERVER_TYPE_CONSTRUCTOR(InboxSendModel)
        void initialize() override {
            INIT_LIST(files, InboxFile) // ?
        }
        STRING_FIELD(inboxId)
        STRING_FIELD(message) // ?
        STRING_FIELD(requestId)
        LIST_FIELD(files, InboxFile) // ?
        INT64_FIELD(version)
    };

    class InboxMessageServer : public utils::TypedObject
    {
    public:
        ENDPOINT_SERVER_TYPE_CONSTRUCTOR(InboxMessageServer);
        void initialize() override {}
        STRING_FIELD(message)
        STRING_FIELD(store)
        LIST_FIELD(files, std::string)
        INT64_FIELD(version)
    };

    class InboxGetPublicViewResult : public utils::TypedObject
    {
    public:
        ENDPOINT_SERVER_TYPE_CONSTRUCTOR(InboxGetPublicViewResult)
        void initialize() override {
        }
        STRING_FIELD(inboxId)
        INT64_FIELD(version)
        VAR_FIELD(publicData)
    };

    class InboxDeletedEventData : public utils::TypedObject
    {
    public:
        ENDPOINT_SERVER_TYPE_CONSTRUCTOR(InboxDeletedEventData)
        void initialize() override {
        }
        STRING_FIELD(inboxId)
    };

    class InboxDeleteModel : public utils::TypedObject
    {
    public:
        ENDPOINT_SERVER_TYPE_CONSTRUCTOR(InboxDeleteModel)
        void initialize() override {
        }
        STRING_FIELD(inboxId)
    };

    class InboxStatChangedEventData : public utils::TypedObject
    {
    public:
        ENDPOINT_SERVER_TYPE_CONSTRUCTOR(InboxStatChangedEventData)
        void initialize() override {
        }
        STRING_FIELD(inboxId)
        INT64_FIELD(lastSubmitDate)
        INT64_FIELD(submits)
        STRING_FIELD(type)
    };

} // server
} // inbox
} // endpoint
} // privmx



#endif // _PRIVMXLIB_ENDPOINT_SERVER_TYPES_HPP_