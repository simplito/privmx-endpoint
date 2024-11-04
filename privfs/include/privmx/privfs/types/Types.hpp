/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_PRIVFS_TYPES_HPP_
#define _PRIVMXLIB_PRIVFS_TYPES_HPP_

#include <privmx/utils/TypedObject.hpp>
#include <privmx/utils/TypesMacros.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/ExtKey.hpp>

namespace privmx {
namespace privfs {
namespace types {

namespace transfer {
    class TransferData;
}
namespace block {
    class BlocksInfoData;
}

class MasterRecordLevel1 : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(MasterRecordLevel1)

    
    void initialize() override {
        initializeObject({"masterSeed", "dataVersion", "recovery", "l2Key"});
    }
    STRING_FIELD(masterSeed)
    STRING_FIELD(dataVersion)
    STRING_FIELD(recovery)
    STRING_FIELD(l2Key)
};

class MasterRecordLevel2 : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(MasterRecordLevel2)
    void initialize() override {
        initializeObject({"adminKey"});
    }
    STRING_FIELD(adminKey)
};

class MasterRecord : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(MasterRecord)
    void initialize() override {
        INIT_OBJECT(l1, MasterRecordLevel1)
        INIT_OBJECT(l2, MasterRecordLevel2)

    }
    OBJECT_FIELD(l1, MasterRecordLevel1)
    OBJECT_FIELD(l2, MasterRecordLevel2)
};

class Identity : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(Identity)
    //username: string;
    //wif: string;
    
    void initialize() override {
        initializeObject({"username", "wif"});
    }
    STRING_FIELD(username)
    STRING_FIELD(wif)
};

class SectionExtra : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(SectionExtra)
    //openOnFirstLogin: boolean;
    //isMeetingParent?: boolean;
    //isMeeting?: boolean;
    //meetingWelcomeMessage?: string;
    //meetingDescription?: string;
    //meetingDuration?: number;
    //meetingStart?: number;
    
    void initialize() override {
        initializeObject({"openOnFirstLogin", "isMeetingParent", "isMeeting", "meetingWelcomeMessage", "meetingDescription", "meetingDuration", "meetingStart"});
    }
    
    BOOL_FIELD(openOnFirstLogin)
    BOOL_FIELD(isMeetingParent)
    BOOL_FIELD(isMeeting)
    STRING_FIELD(meetingWelcomeMessage)
    STRING_FIELD(meetingDescription)
    INT64_FIELD(meetingDuration)
    INT64_FIELD(meetingStart)
};

class ReadInfo : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(ReadInfo)
    //token: PmxApi.api.fetchToken.FetchTokenId; -- string
    //kvdbId: PmxApi.api.kvdb.KvdbId; -- string
    //kvdbEntryId: PmxApi.api.kvdb.EntryKeyHex; -- string
    //kvdbEntryEncKey: PmxApi.api.core.Base64; -- string
    //sinkId: PmxApi.api.sink.Sid; -- string
    
    void initialize() override {
        initializeObject({"token", "kvdbId", "kvdbEntryId", "kvdbEntryEncKey", "sinkId"});
    }
    STRING_FIELD(token)
    STRING_FIELD(kvdbId)
    STRING_FIELD(kvdbEntryId)
    STRING_FIELD(kvdbEntryEncKey)
    STRING_FIELD(sinkId)
};

class Module : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(Module)
    //enabled: boolean
    //data: string}
    
    void initialize() override {
        initializeObject({"enabled", "data"});
    }
    BOOL_FIELD(enabled)
    STRING_FIELD(data)
};

class SectionSecuredData : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(SectionSecuredData)
    //name: string;
    //modules: {[module: string]: {enabled: boolean, data: string}};
    //extraOptions: SectionExtra;
    //description: string;
    
    void initialize() override {
        initializeObject({"name", "description"});
        INIT_MAP(modules, Module)
        INIT_OBJECT(extraOptions, SectionExtra)
    }
    STRING_FIELD(name)
    MAP_FIELD(modules, Module)
    OBJECT_FIELD(extraOptions, SectionExtra)
    STRING_FIELD(description)
};
class SubidentyData : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(SubidentyData)
    //identity: {username: string, wif: string}; -- Identity
    //pubKey: PmxApi.api.core.Base64; -- string
    //sectionId: string; -- string
    //sectionKeyId: string; -- string
    //sectionKey: PmxApi.api.core.Base64; -- string
    //sectionData: section.SectionSecuredData; -- SectionSecuredData
    //meetingId?: PmxMeetingApi.api.meeting.MeetingId; -- VAR
    //readInfo: ReadInfo; -- ReadInfo
    
    void initialize() override {
        initializeObject({"pubKey", "sectionId", "sectionKeyId", "sectionKey"});
        INIT_OBJECT(identity, Identity)
        INIT_OBJECT(sectionData, SectionSecuredData)
        INIT_VAR(meetingId)
        INIT_OBJECT(readInfo, ReadInfo)
    }
    OBJECT_FIELD(identity, Identity)
    STRING_FIELD(pubKey)
    STRING_FIELD(sectionId)
    STRING_FIELD(sectionKeyId)
    STRING_FIELD(sectionKey)
    OBJECT_FIELD(sectionData, SectionSecuredData)
    VAR_FIELD(meetingId)
    OBJECT_FIELD(readInfo, ReadInfo)
};
class Sticker : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(Sticker)
    //u: core.Username; -- string
    //t: core.Timestamp; -- string
    //s: StickerId; -- string
    void initialize() override {
        initializeObject({"u", "t", "s"});
    }
    STRING_FIELD(u)
    STRING_FIELD(t)
    STRING_FIELD(s)
};

class MessageAttachmentData : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(MessageAttachmentData)
    void initialize() override {
        initializeObject({"name", "mimeType", "size", "key"});
        INIT_LIST(blocks, std::string)
    }
    STRING_FIELD(name)
    STRING_FIELD(mimeType)
    LIST_FIELD(blocks, std::string)
    INT32_FIELD(size)
    STRING_FIELD(key)
};
class SerializedReceiver : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(SerializedReceiver)
    //name: string; -- string
    //hashmail: string; -- string
    //pub58: string; -- string
    //sinkPub58: string; -- string
    //sent: boolean; -- bool
    void initialize() override {
        initializeObject({"name", "hashmail", "pub58", "sinkPub58", "sent"});
    }
    STRING_FIELD(name)
    STRING_FIELD(hashmail)
    STRING_FIELD(pub58)
    STRING_FIELD(sinkPub58)
    BOOL_FIELD(sent)

};
class SerializedSender : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(SerializedSender)
    //name: string; -- string
    //hashmail: string; -- string
    //pub58: string; -- string
    void initialize() override {
        initializeObject({"name", "hashmail", "pub58"});
    }
    STRING_FIELD(name)
    STRING_FIELD(hashmail)
    STRING_FIELD(pub58)
};
class SerializedMessage : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(SerializedMessage)
    //msgId: string; -- string
    //createDate: number; -- int64
    //text: string; -- string
    //title: string; -- string
    //inReplyTo: string; -- string
    //forwarded: string; -- string
    //attachments: MessageAttachmentData[]; --deprecated
    //sender: SerializedSender; -- SerializedSender
    //sid: string; -- string
    //outerSignatory: string, -- string
    //receivers: SerializedReceiver[];-- List<SerializedReceiver>
    //type: string; -- string
    //contentType: string; -- string
    //deleted: boolean; -- bool

    //data: var; -- var
    void initialize() override {
        initializeObject({"msgId", "createDate", "text", "title", "inReplyTo", "forwarded", "sid", "outerSignatory", "type", "contentType", "deleted"});
        INIT_OBJECT(sender, SerializedSender)
        INIT_LIST(receivers, SerializedReceiver)
        INIT_VAR(data)
    }
    STRING_FIELD(msgId)
    INT64_FIELD(createDate)
    STRING_FIELD(text)
    STRING_FIELD(title)
    STRING_FIELD(inReplyTo)
    STRING_FIELD(forwarded)
    OBJECT_FIELD(sender, SerializedSender)
    STRING_FIELD(sid)
    STRING_FIELD(outerSignatory)
    LIST_FIELD(receivers, SerializedReceiver)
    STRING_FIELD(type)
    STRING_FIELD(contentType)
    BOOL_FIELD(deleted)
    VAR_FIELD(data)
};

// class SerializedMessageFull : public utils::TypedObject
// {    
// public:
//     CORE_TYPE_CONSTRUCTOR(SerializedMessageFull)
//     void initialize() override {
//         initializeObject({"signature"});
//         INIT_OBJECT(data, SerializedMessage)
//     }
//     STRING_FIELD(signature)
//     OBJECT_FIELD(data, SerializedMessage)
// };

class MessageMeta : public utils::TypedObject
{    
public:
    CORE_TYPE_CONSTRUCTOR(MessageMeta)
    void initialize() override {
        initializeObject({"modId", "msgId", "timestamp"});
        INIT_LIST(stickers, Sticker)
    }
    INT32_FIELD(modId)
    INT32_FIELD(msgId)
    STRING_FIELD(timestamp)
    LIST_FIELD(stickers, Sticker)
};

class MessageDataSender : public utils::TypedObject
{
public: 
    CORE_TYPE_CONSTRUCTOR(MessageDataSender)
    void initialize() override {
        initializeObject({"name", "hashmail"});
    }
    STRING_FIELD(name)
    STRING_FIELD(hashmail)
};

class MessageData : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(MessageData)
    void initialize() override {
        initializeObject({"serverDate", "serverId", "msgId", "createDate", "text", "dataType", "title", "type", "contentType", "deleted", "editCount", "lastEdit"});
        INIT_VAR(data)
        INIT_OBJECT(sender, MessageDataSender)
    }
    STRING_FIELD(serverDate)
    INT32_FIELD(serverId)
    STRING_FIELD(msgId)
    INT64_FIELD(createDate)
    STRING_FIELD(text)
    VAR_FIELD(data)
    STRING_FIELD(dataType)
    STRING_FIELD(title)
    OBJECT_FIELD(sender, MessageDataSender)
    STRING_FIELD(type)
    STRING_FIELD(contentType)
    BOOL_FIELD(deleted)
    INT32_FIELD(editCount)
    STRING_FIELD(lastEdit)
};
class MessageDataAndMeta : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(MessageDataAndMeta)
    void initialize() override {
        initializeObject({});
        INIT_OBJECT(data, MessageData)
        INIT_OBJECT(meta, MessageMeta)
    }
    OBJECT_FIELD(data, MessageData)
    OBJECT_FIELD(meta, MessageMeta)
};

class ChatReceiver : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(ChatReceiver)
    void initialize() override {
        initializeObject({"name", "hashmail", "pub58", "sinkPub58"});
    }
    STRING_FIELD(name)
    STRING_FIELD(hashmail)
    STRING_FIELD(pub58)
    STRING_FIELD(sinkPub58)
};

class UserInfo : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(UserInfo)
    void initialize() override {
        initializeObject({"name", "description", "image", "pkiRevision"});
    }
    STRING_FIELD(name)
    STRING_FIELD(description)
    BINARYSTRING_FIELD(image)
    STRING_FIELD(pkiRevision)
};
class UserStatus : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(UserStatus)
    void initialize() override {
        initializeObject({"username", "hashmail", "isOnline", "lastOnlineStateChangeDate", "pkiRevision", "deleted"});
    }
    STRING_FIELD(username)
    STRING_FIELD(hashmail)
    BOOL_FIELD(isOnline)
    INT64_FIELD(lastOnlineStateChangeDate)
    STRING_FIELD(pkiRevision)
    BOOL_FIELD(deleted)
};
class MetaSharing : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(MetaSharing)
    //sharing?: {users: string[], lastUpdated: number}
    void initialize() override {
        initializeObject({"lastUpdated"});
        INIT_LIST(users, std::string)
    }
    INT64_FIELD(lastUpdated)
    LIST_FIELD(users, std::string)
};

class Meta : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(Meta)
    // size: number
    // createDate: number
    // modifiedDate: number
    // mimeType: string
    // originalName: string
    // type: string
    // sharing?: {users: string[], lastUpdated: number}
    // bindedElementId?: string
    void initialize() override {
        initializeObject({"size", "createDate", "modifiedDate", "mimeType", "originalName", "type", "bindedElementId"});
        INIT_OBJECT(sharing, MetaSharing)
    }
    INT32_FIELD(size)
    INT64_FIELD(createDate)
    INT64_FIELD(modifiedDate)
    STRING_FIELD(mimeType)
    STRING_FIELD(originalName)
    STRING_FIELD(type)
    OBJECT_FIELD(sharing, MetaSharing)
    STRING_FIELD(bindedElementId)
};
class ExtraRaw : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(ExtraRaw)
    // meta: any -- var
    // key: string -- string
    // writeKey: string -- string
    void initialize() override {
        initializeObject({"key", "writeKey"});
        INIT_VAR(meta)
    }
    VAR_FIELD(meta)
    STRING_FIELD(key)
    STRING_FIELD(writeKey)
};


namespace core {
    template<typename T>
    class WithKey {
    public:
        using Ptr = Poco::SharedPtr<WithKey<T>>;
        std::string key;
        T data;
    private:
    };

    class MyData {
    public:
    using Ptr = Poco::SharedPtr<MyData>;

    };

    class MasterRecordApiModel : public utils::TypedObject
    {
    public:
        CORE_TYPE_CONSTRUCTOR(MasterRecordApiModel)
        void initialize() override {
            initializeObject({"version", "privData", "privDataL2", "recoveryData", "srpData", "lbkData", "serverKey"});
        }
        STRING_FIELD(version)
        STRING_FIELD(privData)
        STRING_FIELD(privDataL2)
        STRING_FIELD(recoveryData)
        STRING_FIELD(srpData)
        STRING_FIELD(lbkData)
        STRING_FIELD(serverKey)
    };
} // namespace core
namespace message {

    
    
} // message

class SerializedMaeesage : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(SerializedMaeesage)
    void initialize() override {
        INIT_LIST(attachments, MessageAttachmentData)
        INIT_LIST(receivers, SerializedReceiver)
        INIT_OBJECT(sender, SerializedSender)
    }
    STRING_FIELD(msgId)
    INT64_FIELD(createDate)
    STRING_FIELD(text)
    STRING_FIELD(title)
    STRING_FIELD(inReplyTo)
    STRING_FIELD(forwarded)
    LIST_FIELD(attachments, MessageAttachmentData)
    OBJECT_FIELD(sender, SerializedSender)
    STRING_FIELD(sid)
    STRING_FIELD(outerSignatory)
    OBJECT_FIELD(receivers, SerializedReceiver)
    STRING_FIELD(type)
    STRING_FIELD(contentType)
    BOOL_FIELD(deleted)
};


class SerializedMessageFull : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(SerializedMessageFull)
    void initialize() override {
        initializeObject({"signature"});
        INIT_OBJECT(data, SerializedMessage)
    }
    OBJECT_FIELD(data, SerializedMessage)
    STRING_FIELD(signature)
    BOOL_FIELD(serverId)
    BOOL_FIELD(serverDate)
    BOOL_FIELD(editCount)
    BOOL_FIELD(lastEdit)  
};

class SerializedMessageFullEx : public SerializedMessageFull
{
public:
    CORE_TYPE_CONSTRUCTOR_INHERIT(SerializedMessageFullEx, SerializedMessageFull)
    void initialize() override {
        initializeObject({"serverDate", "pub", "sink"});
    }
    INT64_FIELD(serverDate)
    STRING_FIELD(pub)
    STRING_FIELD(sink) 
};


namespace block {
class BlocksInfoData : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(BlocksInfoData)
    void initialize() override {
        initializeObject({"type"});
        INIT_LIST(blocks, std::string)
    }
    LIST_FIELD(blocks, std::string)
    STRING_FIELD(mimeType)
    INT64_FIELD(size)
    STRING_FIELD(key)
    STRING_FIELD(name)
};
    
class BlocksSource : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(BlocksSource)
    void initialize() override {
        initializeObject({"type"});
    }
    STRING_FIELD(type)
};

class DescriptorBlockSource : public BlocksSource
{
public:
    CORE_TYPE_CONSTRUCTOR_INHERIT(DescriptorBlockSource, BlocksSource)
    void initialize() override {
        initializeObject({"type", "did", "signature"});
        type("descriptor");
    }
    STRING_FIELD(did)
    STRING_FIELD(signature)
};

class MessageBlockSource : public BlocksSource
{
public:
    CORE_TYPE_CONSTRUCTOR_INHERIT(MessageBlockSource, BlocksSource)
    void initialize() override {
        initializeObject({"type", "sid", "mid"});
        type("message");
    }
    STRING_FIELD(sid)
    STRING_FIELD(mid)
};

class TransferBlockSource : public BlocksSource
{
public:
    CORE_TYPE_CONSTRUCTOR_INHERIT(TransferBlockSource, BlocksSource)
    void initialize() override {
        initializeObject({"type", "transferId"});
        type("transfer");
    }
    STRING_FIELD(transferId)
};

class ShareBlockSource : public BlocksSource
{
public:
    CORE_TYPE_CONSTRUCTOR_INHERIT(ShareBlockSource, BlocksSource)
    void initialize() override {
        initializeObject({"type", "shareId"});
        type("share");
    }
    STRING_FIELD(shareId)
};

class BlockData : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(BlockData)
    void initialize() override {
        initializeObject({"bid", "data"});
    }
    STRING_FIELD(bid)
    STRING_FIELD(data)
};

class BlocksInfo : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(BlocksInfo)
    void initialize() override {
        initializeObject({"type"});
        INIT_OBJECT(source, BlocksSource)
        INIT_LIST(blocks, std::string)
    }
    LIST_FIELD(blocks, std::string)
    OBJECT_FIELD(source, BlocksSource)
};
    

} // namespace block

namespace transfer {


class TransferData : public utils::TypedObject
{
public:
    CORE_TYPE_CONSTRUCTOR(TransferData)
    void initialize() override {
        initializeObject({"type"});
    }
    STRING_FIELD(type)
};

class TransferById : public TransferData
{
public:
    CORE_TYPE_CONSTRUCTOR_INHERIT(TransferById, TransferData)
    void initialize() override {
        initializeObject({"type", "transferId"});
        type("transfer");
    }
    STRING_FIELD(transferId)
};

class TransferByBlocksData : public TransferData
{
public:
    CORE_TYPE_CONSTRUCTOR_INHERIT(TransferByBlocksData, TransferData)
    void initialize() override {
        initializeObject({"type"});
        type("blocks");
        INIT_LIST(blocks, BlocksData)
    }
    LIST_FIELD(blocks, block::BlockData)
};

class TransferByBlocksInfo : public TransferData
{
public:
    CORE_TYPE_CONSTRUCTOR_INHERIT(TransferByBlocksInfo, TransferData)
    void initialize() override {
        initializeObject({"type"});
        type("blocksInfo");
        INIT_LIST(blocksInfo, block::BlocksInfo)
    }
    LIST_FIELD(blocksInfo, block::BlocksInfo)
};

} // namespace transfer



} // types
} // privfs
} // privmx




#endif // _PRIVMXLIB_PRIVFS_TYPES_HPP_