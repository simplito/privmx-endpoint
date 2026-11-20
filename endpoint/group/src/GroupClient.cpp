/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

// Built on the public methods of GroupApi alone: nothing in this file opens, seals or verifies anything itself.

#include "privmx/endpoint/group/GroupClient.hpp"

#include <algorithm>
#include <set>

#include <privmx/endpoint/core/ConvertedExceptions.hpp>
#include <privmx/endpoint/core/CoreException.hpp>

#include "privmx/endpoint/group/GroupException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::group;

namespace {

bool isNoLocation(const Path& path) {
    return path.size() == 1 && path.front().isId && path.front().value.size() == 0;
}

// `subject + place`. Under a subject a place is at least one segment: "no location" there would bind every value
// of the entity to the same spot. An object with no subject takes a full location as it is.
Path join(const Path& subject, const Path& place) {
    if (subject.empty()) {
        return place;
    }
    if (place.empty() || isNoLocation(place)) {
        throw core::InvalidParamsException("a place under a subject needs at least one segment");
    }
    Path location = subject;
    location.insert(location.end(), place.begin(), place.end());
    return location;
}

std::vector<DecryptItem> placed(const Path& subject, std::vector<DecryptItem> items) {
    for (DecryptItem& item : items) {
        item.location = join(subject, item.location);
    }
    return items;
}

// A Group named by its subject, for something that is about to be wrapped for it or written to it by someone
// who may not be in it. Whoever knows a subject can make a Group under it first, so the caller says who made the
// right one, and the Group's signed policy has to agree.
std::string groupOfSubject(
    GroupApi& api,
    const std::string& contextId,
    const Path& subject,
    const std::string& createdBy
) {
    if (createdBy.empty()) {
        throw core::InvalidParamsException("a Group named by its subject is named with the user who created it");
    }
    const std::string groupId = GroupApi::deriveGroupId(contextId, GroupApi::encodePath(subject));
    const std::string creator = api.getGroupPublicKey(contextId, groupId).creator;
    if (creator != createdBy) {
        throw GroupWrongCreatorException(creator);
    }
    return groupId;
}

// Further recipients named by subject, turned into the IDs GroupApi takes.
EncryptOptions resolved(GroupApi& api, const std::string& contextId, EncryptOptions options) {
    for (EnvelopeRecipient& recipient : options.alsoFor) {
        if (!recipient.groupSubject.empty()) {
            if (!recipient.groupId.empty() || recipient.user.has_value()) {
                throw core::InvalidParamsException("a recipient is one group, by its ID or its subject, or one user");
            }
            recipient.groupId = groupOfSubject(api, contextId, recipient.groupSubject, recipient.groupCreatedBy);
            recipient.groupSubject.clear();
            recipient.groupCreatedBy.clear();
        }
    }
    return options;
}

std::vector<SpaceRecipient> resolvedRecipients(
    GroupApi& api,
    const std::string& contextId,
    std::vector<SpaceRecipient> recipients
) {
    for (SpaceRecipient& recipient : recipients) {
        if (!recipient.groupSubject.empty()) {
            if (!recipient.groupId.empty() || recipient.user.has_value()) {
                throw core::InvalidParamsException("a recipient is one group, by its ID or its subject, or one user");
            }
            recipient.groupId = groupOfSubject(api, contextId, recipient.groupSubject, recipient.groupCreatedBy);
            recipient.groupSubject.clear();
            recipient.groupCreatedBy.clear();
        }
    }
    return recipients;
}

std::optional<core::ContainerPolicy> policyOf(const std::optional<GroupRules>& rules) {
    if (!rules.has_value()) {
        return std::nullopt;
    }
    core::ContainerPolicy policy{};
    policy.addMembers = rules->addMembers;
    policy.removeMembers = rules->removeMembers;
    policy.update = rules->updateMeta;
    return policy;
}

// What createFixedGroup makes: every member a manager, and nobody may add, remove or change the rules or the
// roles - all of it signed.
bool isFixed(const Group& state) {
    return state.users.empty() &&
        state.policy.addMembers.value_or("") == "none" &&
        state.policy.removeMembers.value_or("") == "none" &&
        state.policy.updatePolicy.value_or("") == "none";
}

} // namespace

// -- files and sequences ---------------------------------------------------------------------------------

core::Buffer GroupFileWriter::encryptChunk(const core::Buffer& plainChunk) {
    return _api.encryptFileChunk(_handle, plainChunk);
}
core::Buffer GroupFileWriter::finish() {
    return _api.finishFileEncryption(_handle);
}

core::Buffer GroupFileReader::decryptChunk(const core::Buffer& cipherChunk) {
    return _api.decryptFileChunk(_handle, cipherChunk);
}
CipherRange GroupFileReader::getCipherRange(int64_t from, int64_t to) {
    return _api.getFileCipherRange(_handle, from, to);
}
int64_t GroupFileReader::seek(int64_t position) {
    return _api.seekInEncryptedFile(_handle, position);
}
DecryptedFileInfo GroupFileReader::finish() {
    return _api.finishFileDecryption(_handle);
}

core::Buffer GroupSequenceWriter::getHeader() {
    return _api.getSequenceHeader(_handle);
}
SequenceAppendResult GroupSequenceWriter::append(const core::Buffer& data) {
    return _api.appendToSequence(_handle, data);
}
core::Buffer GroupSequenceWriter::checkpoint() {
    return _api.checkpointSequence(_handle);
}
core::Buffer GroupSequenceWriter::finish() {
    return _api.finishSequence(_handle);
}

SequenceItem GroupSequenceReader::read(const core::Buffer& item) {
    return _api.readSequenceItem(_handle, item);
}
SequenceMarkInfo GroupSequenceReader::verify(const core::Buffer& mark) {
    return _api.verifySequenceMark(_handle, mark);
}
SpaceOrigin GroupSequenceReader::getSpaceOrigin() {
    return _api.getSpaceSequenceOrigin(_handle);
}
void GroupSequenceReader::close() {
    _api.closeSequence(_handle);
}

// -- GroupHandle -------------------------------------------------------------------------------------------

Path GroupHandle::at(const Path& place) const {
    return join(_subject, place);
}

Group GroupHandle::getState() {
    return _api.getGroup(_groupId);
}
core::PagingList<GroupLogEntry> GroupHandle::getLog(const core::PagingQuery& query) {
    return _api.getGroupLog(_groupId, query);
}

core::Buffer GroupHandle::encrypt(const Path& place, const core::Buffer& data, const EncryptOptions& options) {
    return _api.encrypt(_groupId, at(place), data, resolved(_api, _contextId, options));
}
DecryptedEnvelope GroupHandle::decrypt(const Path& place, const core::Buffer& envelope, const DecryptOptions& options) {
    return _api.decrypt(_groupId, at(place), envelope, options);
}
std::vector<DecryptResult> GroupHandle::decryptMany(const std::vector<DecryptItem>& items) {
    return _api.decryptMany(_groupId, placed(_subject, items));
}
DecryptedOutsiderEnvelope GroupHandle::decryptFromOutsider(
    const Path& place,
    const core::Buffer& envelope,
    const DecryptOptions& options
) {
    return _api.decryptFromOutsider(_groupId, at(place), envelope, options);
}
DecryptedAnonymousEnvelope GroupHandle::decryptAnonymous(const Path& place, const core::Buffer& envelope) {
    return _api.decryptAnonymous(_groupId, at(place), envelope);
}

GroupFileWriter GroupHandle::beginFileEncryption(const Path& place, const EncryptOptions& options) {
    return GroupFileWriter(_api, _api.beginFileEncryption(_groupId, at(place), resolved(_api, _contextId, options)));
}
GroupFileReader GroupHandle::beginFileDecryption(
    const Path& place,
    const core::Buffer& envelope,
    const DecryptOptions& options
) {
    return GroupFileReader(_api, _api.beginFileDecryption(_groupId, at(place), envelope, options));
}
GroupFileReader GroupHandle::beginFileDecryptionFromOutsider(
    const Path& place,
    const core::Buffer& envelope,
    const DecryptOptions& options
) {
    return GroupFileReader(_api, _api.beginFileDecryptionFromOutsider(_groupId, at(place), envelope, options));
}
GroupFileReader GroupHandle::beginAnonymousFileDecryption(const Path& place, const core::Buffer& envelope) {
    return GroupFileReader(_api, _api.beginAnonymousFileDecryption(_groupId, at(place), envelope));
}

GroupSequenceWriter GroupHandle::beginSequence(const Path& place, int64_t checkpointEvery) {
    return GroupSequenceWriter(_api, _api.beginSequence(_groupId, at(place), checkpointEvery));
}
GroupSequenceReader GroupHandle::openSequence(
    const Path& place,
    const core::Buffer& header,
    const DecryptOptions& options,
    const std::optional<core::Buffer>& resumeFrom
) {
    return GroupSequenceReader(_api, _api.openSequence(_groupId, at(place), header, options, resumeFrom));
}

void GroupHandle::addMembers(const std::vector<GroupMemberToAdd>& members) {
    _api.addGroupMembers(_groupId, members);
}
int64_t GroupHandle::removeMembers(const std::vector<std::string>& userIds) {
    return _api.removeGroupMembers(_groupId, userIds);
}
int64_t GroupHandle::reseatMembers(const std::vector<std::string>& userIds) {
    return _api.reseatGroupMembers(_groupId, userIds);
}
void GroupHandle::setRoles(const std::vector<GroupRoleChange>& changes) {
    _api.setGroupRoles(_groupId, changes);
}
int64_t GroupHandle::rotateKey() {
    return _api.rotateGroupKey(_groupId);
}
void GroupHandle::updatePublicMeta(const core::Buffer& meta, int64_t version) {
    _api.updateGroupPublicMeta(_groupId, meta, version);
}
void GroupHandle::updatePrivateMeta(const core::Buffer& meta, int64_t version) {
    _api.updateGroupPrivateMeta(_groupId, meta, version);
}
void GroupHandle::updateRules(const GroupRulesUpdate& rules) {
    _api.updateGroupRules(_groupId, rules);
}
void GroupHandle::setVisibility(const std::string& visibleTo) {
    _api.setGroupVisibility(_groupId, visibleTo);
}
void GroupHandle::deleteGroup() {
    _api.deleteGroup(_groupId);
}

void GroupHandle::sendCustomEvent(
    const std::string& channelName,
    const core::Buffer& eventData,
    const std::vector<std::string>& users
) {
    _api.sendCustomEvent(_groupId, channelName, eventData, users);
}
std::string GroupHandle::buildSubscriptionQuery(EventType eventType) {
    return _api.buildSubscriptionQuery(eventType, EventSelectorType::GROUP_ID, _groupId);
}
std::string GroupHandle::buildCustomEventSubscriptionQuery(const std::string& channelName) {
    return _api.buildCustomEventSubscriptionQuery(channelName, EventSelectorType::GROUP_ID, _groupId);
}

// -- GroupOutsider -----------------------------------------------------------------------------------------

GroupOutsider GroupOutsider::anonymous(GroupApi api, const GroupPublicKey& key, const Path& subject) {
    GroupOutsider writer;
    writer._api = std::move(api);
    writer._groupId = key.groupId;
    writer._groupPubKey = key.pubKey;
    writer._subject = subject;
    return writer;
}

Path GroupOutsider::at(const Path& place) const {
    return join(_subject, place);
}

core::Buffer GroupOutsider::encrypt(const Path& place, const core::Buffer& data, const EncryptOptions& options) {
    if (!_contextId.empty()) {
        return _api.encryptAsOutsider(_contextId, _groupId, at(place), data, resolved(_api, _contextId, options));
    }
    if (!options.alsoFor.empty()) {
        throw core::InvalidParamsException("an anonymous writer has no further recipients");
    }
    return _api.encryptAnonymously(_groupId, _groupPubKey, at(place), data);
}

GroupFileWriter GroupOutsider::beginFileEncryption(const Path& place, const EncryptOptions& options) {
    if (!_contextId.empty()) {
        return GroupFileWriter(
            _api,
            _api.beginFileEncryptionAsOutsider(_contextId, _groupId, at(place), resolved(_api, _contextId, options))
        );
    }
    if (!options.alsoFor.empty()) {
        throw core::InvalidParamsException("an anonymous writer has no further recipients");
    }
    return GroupFileWriter(_api, _api.beginFileEncryptionAnonymously(_groupId, _groupPubKey, at(place)));
}

// -- Space ---------------------------------------------------------------------------------------------------

Path Space::at(const Path& place) const {
    return join(_subject, place);
}

SpaceState Space::getState() {
    return _api.getSpace(_spaceId);
}
core::Buffer Space::encrypt(const Path& place, const core::Buffer& data) {
    return _api.encryptInSpace(_spaceId, at(place), data);
}
DecryptedSpaceEnvelope Space::decrypt(const Path& place, const core::Buffer& envelope, const DecryptOptions& options) {
    return _api.decryptInSpace(_spaceId, at(place), envelope, options);
}
std::vector<SpaceDecryptResult> Space::decryptMany(const std::vector<DecryptItem>& items) {
    return _api.decryptManyInSpace(_spaceId, placed(_subject, items));
}
GroupFileWriter Space::beginFileEncryption(const Path& place) {
    return GroupFileWriter(_api, _api.beginFileEncryptionInSpace(_spaceId, at(place)));
}
GroupFileReader Space::beginFileDecryption(
    const Path& place,
    const core::Buffer& envelope,
    const DecryptOptions& options
) {
    return GroupFileReader(_api, _api.beginFileDecryptionInSpace(_spaceId, at(place), envelope, options));
}
GroupSequenceWriter Space::beginSequence(const Path& place, int64_t checkpointEvery) {
    return GroupSequenceWriter(_api, _api.beginSequenceInSpace(_spaceId, at(place), checkpointEvery));
}
GroupSequenceReader Space::openSequence(
    const Path& place,
    const core::Buffer& header,
    const DecryptOptions& options,
    const std::optional<core::Buffer>& resumeFrom
) {
    return GroupSequenceReader(_api, _api.openSequenceInSpace(_spaceId, at(place), header, options, resumeFrom));
}

void Space::addRecipients(const std::vector<SpaceRecipient>& recipients) {
    _api.addSpaceRecipients(_spaceId, resolvedRecipients(_api, _contextId, recipients));
}
int64_t Space::removeRecipients(const std::vector<SpaceRecipientRef>& recipients) {
    std::vector<SpaceRecipientRef> resolved = recipients;
    for (SpaceRecipientRef& recipient : resolved) {
        if (!recipient.groupSubject.empty()) {
            if (!recipient.groupId.empty()) {
                throw core::InvalidParamsException("a recipient Group is named by its ID or by its subject, not both");
            }
            recipient.groupId = GroupApi::deriveGroupId(_contextId, GroupApi::encodePath(recipient.groupSubject));
            recipient.groupSubject.clear();
        }
    }
    return _api.removeSpaceRecipients(_spaceId, resolved);
}
int64_t Space::rotateKey() {
    return _api.rotateSpaceKey(_spaceId);
}
void Space::updatePublicMeta(const core::Buffer& meta, int64_t version) {
    _api.updateSpacePublicMeta(_spaceId, meta, version);
}
void Space::updatePrivateMeta(const core::Buffer& meta, int64_t version) {
    _api.updateSpacePrivateMeta(_spaceId, meta, version);
}
void Space::deleteSpace() {
    _api.deleteSpace(_spaceId);
}

// -- GroupClient -------------------------------------------------------------------------------------------

GroupClient GroupClient::create(GroupApi groupApi, const std::string& contextId) {
    GroupClient client;
    client._api = std::move(groupApi);
    client._contextId = contextId;
    return client;
}

std::string GroupClient::groupIdOf(const Path& subject) const {
    return GroupApi::deriveGroupId(_contextId, GroupApi::encodePath(subject));
}

std::string GroupClient::create(
    const std::optional<Path>& subject,
    const std::vector<GroupMemberToAdd>& members,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::optional<GroupRules>& rules,
    const std::string& visibleTo
) {
    std::vector<core::UserWithPubKey> users;
    std::vector<core::UserWithPubKey> managers;
    for (const GroupMemberToAdd& member : members) {
        if (member.role != "user" && member.role != "manager") {
            throw core::InvalidParamsException("a member's role is \"user\" or \"manager\"");
        }
        (member.role == "manager" ? managers : users).push_back(member.user);
    }
    try {
        return _api.createGroup(
            _contextId, users, managers, publicMeta, privateMeta, policyOf(rules),
            subject.has_value() ? std::optional<core::Buffer>(GroupApi::encodePath(subject.value())) : std::nullopt,
            visibleTo
        );
    } catch (const server::DuplicateResourceIdException& e) {
        // The subject has a Group already. If the caller did not make it, someone else did.
        throw GroupAlreadyExistsException(e);
    }
}

GroupHandle GroupClient::createGroup(
    const Path& subject,
    const std::vector<GroupMemberToAdd>& members,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::optional<GroupRules>& rules,
    const std::string& visibleTo
) {
    return GroupHandle(_api, _contextId, create(subject, members, publicMeta, privateMeta, rules, visibleTo), subject);
}

void GroupClient::check(const OpenGroupItem& item, const Group& state) {
    if (state.contextId != _contextId) {
        throw core::InvalidParamsException("a Group of another Context");
    }
    if (item.fixedMembers.has_value()) {
        const std::set<std::string> held(state.managers.begin(), state.managers.end());
        const std::set<std::string> expected(item.fixedMembers->begin(), item.fixedMembers->end());
        if (!isFixed(state) || held != expected) {
            throw GroupMembershipMismatchException("not the fixed Group of exactly the expected users");
        }
        return;
    }
    if (isFixed(state) && !item.pinnedGroupId.has_value()) {
        // Anyone can make a fixed Group under a subject they chose; it is opened only by someone who names its
        // members.
        throw GroupMembershipMismatchException("a fixed Group: open it with openFixedGroup");
    }
    if (item.createdBy.has_value()) {
        // The signer of the first statement, verified with the rest of the history - not the Bridge's `creator`.
        const auto first = _api.getGroupLog(
            state.groupId, core::PagingQuery{.skip = 0, .limit = 1, .sortOrder = "asc"}
        );
        if (first.readItems.empty() || first.readItems.front().author != item.createdBy.value()) {
            throw GroupWrongCreatorException(first.readItems.empty() ? std::string() : first.readItems.front().author);
        }
    }
    if (item.pinnedGroupId.has_value()) {
        _api.pinGroupToSubject(_contextId, item.subject, item.pinnedGroupId.value());
    }
}

GroupHandle GroupClient::openGroup(const Path& subject, const OpenGroupOptions& options) {
    const std::string groupId = groupIdOf(subject);
    check(
        OpenGroupItem{.subject = subject, .createdBy = options.createdBy, .fixedMembers = {}, .pinnedGroupId = {}},
        _api.getGroup(groupId)
    );
    return GroupHandle(_api, _contextId, groupId, subject);
}

GroupHandle GroupClient::openPinnedGroup(const Path& subject, const std::string& groupId) {
    GroupApi::encodePath(subject); // a subject, said: an unbound Group is opened with openUnboundGroup
    check(
        OpenGroupItem{.subject = subject, .createdBy = {}, .fixedMembers = {}, .pinnedGroupId = groupId},
        _api.getGroup(groupId)
    );
    return GroupHandle(_api, _contextId, groupId, subject);
}

GroupHandle GroupClient::createFixedGroup(
    const Path& subject,
    const std::vector<core::UserWithPubKey>& users,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta
) {
    core::ContainerPolicy policy{};
    policy.addMembers = "none";
    policy.removeMembers = "none";
    policy.updatePolicy = "none";
    try {
        return GroupHandle(
            _api, _contextId,
            // All of them managers: a Bridge may require the creator to be one, and here nobody is more than another.
            _api.createGroup(_contextId, {}, users, publicMeta, privateMeta, policy, GroupApi::encodePath(subject)),
            subject
        );
    } catch (const server::DuplicateResourceIdException& e) { throw GroupAlreadyExistsException(e); }
}

GroupHandle GroupClient::openFixedGroup(const Path& subject, const std::vector<std::string>& userIds) {
    const std::string groupId = groupIdOf(subject);
    check(
        OpenGroupItem{.subject = subject, .createdBy = {}, .fixedMembers = userIds, .pinnedGroupId = {}},
        _api.getGroup(groupId)
    );
    return GroupHandle(_api, _contextId, groupId, subject);
}

std::vector<OpenGroupResult> GroupClient::openGroups(const std::vector<OpenGroupItem>& items) {
    std::vector<std::string> groupIds;
    groupIds.reserve(items.size());
    for (const OpenGroupItem& item : items) {
        groupIds.push_back(item.pinnedGroupId.has_value() ? item.pinnedGroupId.value() : groupIdOf(item.subject));
    }
    const std::vector<GroupResult> states = _api.getGroups(groupIds);
    std::vector<OpenGroupResult> results;
    results.reserve(items.size());
    for (std::size_t i = 0; i < items.size(); ++i) {
        OpenGroupResult result{.statusCode = states.at(i).statusCode, .group = {}};
        if (result.statusCode == 0) {
            try {
                check(items[i], states[i].group);
                result.group = GroupHandle(_api, _contextId, groupIds[i], items[i].subject);
            } catch (const core::Exception& e) { result.statusCode = e.getCode(); }
        }
        results.push_back(std::move(result));
    }
    return results;
}

GroupHandle GroupClient::createUnboundGroup(
    const std::vector<GroupMemberToAdd>& members,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::optional<GroupRules>& rules,
    const std::string& visibleTo
) {
    return GroupHandle(
        _api, _contextId, create(std::nullopt, members, publicMeta, privateMeta, rules, visibleTo), Path{}
    );
}

GroupHandle GroupClient::openUnboundGroup(const std::string& groupId) {
    if (_api.getGroup(groupId).contextId != _contextId) {
        throw core::InvalidParamsException("a Group of another Context");
    }
    return GroupHandle(_api, _contextId, groupId, Path{});
}

std::vector<SpaceRecipient> GroupClient::resolve(const std::vector<SpaceRecipient>& recipients) {
    return resolvedRecipients(_api, _contextId, recipients);
}

Space GroupClient::createSpaceFor(
    const Path& subject,
    const std::vector<SpaceRecipient>& recipients,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta
) {
    try {
        return Space(
            _api, _contextId,
            _api.createSpace(_contextId, resolve(recipients), publicMeta, privateMeta, GroupApi::encodePath(subject)),
            subject
        );
    } catch (const server::DuplicateResourceIdException& e) { throw GroupAlreadyExistsException(e); }
}

Space GroupClient::openSpace(const Path& subject, const OpenGroupOptions& options) {
    const std::string spaceId = GroupApi::deriveSpaceId(_contextId, GroupApi::encodePath(subject));
    const SpaceState state = _api.getSpace(spaceId);
    if (options.createdBy.has_value() && state.createdBy != options.createdBy.value()) {
        throw GroupWrongCreatorException(state.createdBy);
    }
    return Space(_api, _contextId, spaceId, subject);
}

Space GroupClient::createUnboundSpace(
    const std::vector<SpaceRecipient>& recipients,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta
) {
    return Space(_api, _contextId, _api.createSpace(_contextId, resolve(recipients), publicMeta, privateMeta), Path{});
}

Space GroupClient::openUnboundSpace(const std::string& spaceId) {
    if (_api.getSpace(spaceId).contextId != _contextId) {
        throw core::InvalidParamsException("a Space of another Context");
    }
    return Space(_api, _contextId, spaceId, Path{});
}

GroupOutsider GroupClient::openForWriting(const Path& subject, const std::string& createdBy) {
    GroupOutsider writer;
    writer._api = _api;
    writer._contextId = _contextId;
    writer._groupId = groupOfSubject(_api, _contextId, subject, createdBy);
    writer._subject = subject;
    return writer;
}

GroupPublicKey GroupClient::getPublicKey(const Path& subject, const std::string& createdBy) {
    groupOfSubject(_api, _contextId, subject, createdBy);
    return _api.getGroupPublicKey(_contextId, groupIdOf(subject));
}

// The envelope says which Group it was written in; the place it was found at says which Group that should be.
// Checked on the plain header first, and it is that header the signature covers.
void GroupClient::requireHome(
    const Path& authorSubject,
    const core::Buffer& envelope,
    const std::optional<std::string>& homeCreatedBy
) {
    const std::string homeId = groupIdOf(authorSubject);
    if (GroupApi::peekEnvelope(envelope).groupId != homeId) {
        throw EnvelopeWrongGroupException("not written in the Group of the author's subject");
    }
    if (homeCreatedBy.has_value()) {
        groupOfSubject(_api, _contextId, authorSubject, homeCreatedBy.value());
    }
}

DecryptedSharedEnvelope GroupClient::decryptShared(
    const Path& authorSubject,
    const Path& place,
    const core::Buffer& envelope,
    const DecryptOptions& options,
    const std::optional<std::string>& homeCreatedBy
) {
    requireHome(authorSubject, envelope, homeCreatedBy);
    return _api.decryptShared(_contextId, join(authorSubject, place), envelope, options);
}

GroupFileReader GroupClient::beginSharedFileDecryption(
    const Path& authorSubject,
    const Path& place,
    const core::Buffer& envelope,
    const DecryptOptions& options,
    const std::optional<std::string>& homeCreatedBy
) {
    requireHome(authorSubject, envelope, homeCreatedBy);
    return GroupFileReader(
        _api, _api.beginSharedFileDecryption(_contextId, join(authorSubject, place), envelope, options)
    );
}
