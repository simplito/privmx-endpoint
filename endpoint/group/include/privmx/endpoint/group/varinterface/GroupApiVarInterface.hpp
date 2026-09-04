#ifndef _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIVARINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIVARINTERFACE_HPP_

#include <Poco/Dynamic/Var.h>

#include "privmx/endpoint/group/GroupApi.hpp"
#include "privmx/endpoint/group/VarDeserializer.hpp"
#include "privmx/endpoint/group/VarSerializer.hpp"

namespace privmx {
namespace endpoint {
namespace group {

class GroupApiVarInterface {
public:
    enum METHOD {
        Create = 0,
        CreateGroup = 1,
        AddGroupMembers = 2,
        RemoveGroupMembers = 3,
        UpdateGroup = 4,
        DeleteGroup = 5,
        GetGroup = 6,
        ListGroups = 7,
        SubscribeFor = 8,
        UnsubscribeFrom = 9,
        BuildSubscriptionQuery = 10,
        // Append only — these ints are the ABI the bindings dispatch on.
        Encrypt = 11,
        Decrypt = 12,
        EncryptAnonymously = 13,
        BeginFileEncryption = 14,
        EncryptFileChunk = 15,
        BeginFileDecryption = 16,
        DecryptFileChunk = 17,
        FinishFileEncryption = 18,
        FinishFileDecryption = 19,
        BeginFileEncryptionAnonymously = 20,
        SeekInEncryptedFile = 21,
    };

    GroupApiVarInterface(core::Connection connection, const core::VarSerializer& serializer)
        : _connection(std::move(connection)), _serializer(serializer) {}

    Poco::Dynamic::Var create(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var createGroup(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var addGroupMembers(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var removeGroupMembers(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var updateGroup(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var deleteGroup(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getGroup(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var listGroups(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var subscribeFor(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var unsubscribeFrom(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var buildSubscriptionQuery(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var encrypt(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var decrypt(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var encryptAnonymously(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var beginFileEncryption(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var encryptFileChunk(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var beginFileDecryption(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var decryptFileChunk(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var finishFileEncryption(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var finishFileDecryption(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var beginFileEncryptionAnonymously(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var seekInEncryptedFile(const Poco::Dynamic::Var& args);

    Poco::Dynamic::Var exec(METHOD method, const Poco::Dynamic::Var& args);

    GroupApi getApi() const { return _groupApi; }

private:
    static std::map<METHOD, Poco::Dynamic::Var (GroupApiVarInterface::*)(const Poco::Dynamic::Var&)> methodMap;

    core::Connection _connection;
    GroupApi _groupApi;
    core::VarDeserializer _deserializer;
    core::VarSerializer _serializer;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIVARINTERFACE_HPP_
