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
        // 4 was UpdateGroup, which split into 22/23/24. Burned, not reused, and left out of `methodMap` so a
        // stale wrapper calling it fails loudly instead of dispatching to whatever lands here next.
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
        SendCustomEvent = 22,
        BuildCustomEventSubscriptionQuery = 23,
        UpdateGroupPublicMeta = 24,
        UpdateGroupPrivateMeta = 25,
        UpdateGroupPolicy = 26,
        RotateGroupKey = 27,
        RenewLeaf = 28,
        DecryptMany = 29,
        EncryptAsOutsider = 30,
        DecryptFromOutsider = 31,
        DecryptAnonymous = 32,
        DecryptShared = 33,
        PeekEnvelope = 34,
        NoLocation = 35,
        IdFromString = 36,
        DeriveGroupId = 37,
        GetGroups = 38,
        GetGroupPublicKey = 39,
        SetGroupVisibility = 40,
        ReseatGroupMembers = 41,
        SetGroupRoles = 42,
        UpdateGroupRules = 43,
        GetGroupLog = 44,
        BeginFileEncryptionAsOutsider = 45,
        BeginFileDecryptionFromOutsider = 46,
        BeginAnonymousFileDecryption = 47,
        BeginSharedFileDecryption = 48,
        GetFileCipherRange = 49,
        BeginSequence = 50,
        GetSequenceHeader = 51,
        AppendToSequence = 52,
        CheckpointSequence = 53,
        FinishSequence = 54,
        OpenSequence = 55,
        ReadSequenceItem = 56,
        VerifySequenceMark = 57,
        CloseSequence = 58,
        PeekSequenceItem = 59,
        CreateSpace = 60,
        DeriveSpaceId = 61,
        GetSpace = 62,
        ListSpaces = 63,
        DeleteSpace = 64,
        AddSpaceRecipients = 65,
        RemoveSpaceRecipients = 66,
        RotateSpaceKey = 67,
        UpdateSpacePublicMeta = 68,
        UpdateSpacePrivateMeta = 69,
        EncryptInSpace = 70,
        DecryptInSpace = 71,
        DecryptManyInSpace = 72,
        BeginFileEncryptionInSpace = 73,
        BeginFileDecryptionInSpace = 74,
        BeginSequenceInSpace = 75,
        OpenSequenceInSpace = 76,
        GetSpaceSequenceOrigin = 77,
        EncodePath = 78,
        PinGroupToSubject = 79,
        AbortFile = 81,
    };

    GroupApiVarInterface(core::Connection connection, const core::VarSerializer& serializer)
        : _connection(std::move(connection)), _serializer(serializer) {}

    Poco::Dynamic::Var create(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var createGroup(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var addGroupMembers(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var removeGroupMembers(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var rotateGroupKey(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var renewLeaf(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var updateGroupPublicMeta(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var updateGroupPrivateMeta(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var updateGroupPolicy(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var deleteGroup(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getGroup(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var listGroups(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var subscribeFor(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var unsubscribeFrom(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var buildSubscriptionQuery(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var encrypt(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var decrypt(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var encryptAnonymously(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var decryptMany(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var encryptAsOutsider(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var decryptFromOutsider(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var decryptAnonymous(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var decryptShared(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var peekEnvelope(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var noLocation(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var idFromString(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var deriveGroupId(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getGroups(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getGroupPublicKey(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var setGroupVisibility(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var reseatGroupMembers(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var setGroupRoles(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var updateGroupRules(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getGroupLog(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var beginFileEncryption(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var encryptFileChunk(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var beginFileDecryption(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var decryptFileChunk(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var finishFileEncryption(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var finishFileDecryption(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var beginFileEncryptionAnonymously(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var seekInEncryptedFile(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var beginFileEncryptionAsOutsider(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var beginFileDecryptionFromOutsider(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var beginAnonymousFileDecryption(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var beginSharedFileDecryption(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getFileCipherRange(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var beginSequence(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getSequenceHeader(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var appendToSequence(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var checkpointSequence(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var finishSequence(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var openSequence(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var readSequenceItem(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var verifySequenceMark(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var closeSequence(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var peekSequenceItem(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var createSpace(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var deriveSpaceId(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getSpace(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var listSpaces(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var deleteSpace(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var addSpaceRecipients(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var removeSpaceRecipients(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var rotateSpaceKey(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var updateSpacePublicMeta(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var updateSpacePrivateMeta(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var encryptInSpace(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var decryptInSpace(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var decryptManyInSpace(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var beginFileEncryptionInSpace(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var beginFileDecryptionInSpace(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var beginSequenceInSpace(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var openSequenceInSpace(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getSpaceSequenceOrigin(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var encodePath(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var pinGroupToSubject(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var abortFile(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var sendCustomEvent(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var buildCustomEventSubscriptionQuery(const Poco::Dynamic::Var& args);

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
