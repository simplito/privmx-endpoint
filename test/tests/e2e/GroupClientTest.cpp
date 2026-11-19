#include <gtest/gtest.h>
#include "BaseGroupTest.hpp"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/group/GroupApi.hpp>
#include <privmx/endpoint/group/GroupClient.hpp>
#include <privmx/endpoint/group/GroupException.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::group;

/**
 * GroupClient against a running Bridge: Groups and Spaces named by the entity they serve.
 *
 * The three C++ examples of the Group API v2 proposal (chat.cpp, records.cpp, space.cpp), as tests. The functions
 * at the top are the examples' own, changed only where the API was named differently in the end; the tests below
 * call them the way an application would.
 */

static PathSegment name(const std::string& text) { return {false, core::Buffer::from(text)}; }
static PathSegment id(const core::Buffer& bytes) { return {true, bytes}; }
static PathSegment id(const std::string& value) { return {true, GroupApi::idFromString(value)}; }
static DecryptOptions by(const std::string& userId) {
    return DecryptOptions{.expectedAuthor = userId, .anyAuthor = false, .currentEpochOnly = false};
}
static DecryptOptions anyAuthor() {
    return DecryptOptions{.expectedAuthor = "", .anyAuthor = true, .currentEpochOnly = false};
}

// ── chat.cpp ────────────────────────────────────────────────────────────────────────────────────────

struct MessageRow {
    core::Buffer messageId;
    std::string authorId; // the server's claim; decrypt checks it
    core::Buffer body;
};

// The library makes the chat's ID together with the Group: created.id is what the chat row gets.
static CreatedGroup createChat(GroupClient& groups, const std::vector<GroupMemberToAdd>& members) {
    return groups.createGroup({name("chat-app"), name("chat")}, members, {}, core::Buffer::from("Design"));
}

static Path directSubject(std::string me, std::string peer) {
    return {name("chat-app"), name("dm"), id(std::min(me, peer)), id(std::max(me, peer))};
}

// A 1:1 chat is named by its two users: a fixed Group, opened only if it holds exactly those two.
static GroupHandle openDirect(GroupClient& groups, std::string me, std::string peer) {
    return groups.openFixedGroup(directSubject(me, peer), {me, peer});
}

static core::Buffer sendMessage(GroupHandle& chat, const core::Buffer& messageId, const std::string& text) {
    return chat.encrypt({name("message"), id(messageId), name("body")}, core::Buffer::from(text));
}

static std::vector<std::string> loadMessages(GroupHandle& chat, const std::vector<MessageRow>& rows) {
    std::vector<DecryptItem> items;
    for (const auto& row : rows) {
        items.push_back({
            .envelope = row.body,
            .location = {name("message"), id(row.messageId), name("body")},
            .options = by(row.authorId),
        });
    }
    std::vector<std::string> shown;
    for (const auto& result : chat.decryptMany(items)) {
        shown.push_back(result.statusCode == 0 ? result.envelope.data.stdString() : "message could not be verified");
    }
    return shown;
}

// A server: refuse an envelope that is not from the Group's current epoch. No keys, no connection.
static bool mayStore(const core::Buffer& envelope, const std::string& chatGroupId, int64_t currentEpoch) {
    EnvelopeHeader header = GroupApi::peekEnvelope(envelope);
    return header.groupId == chatGroupId && !header.fromOutsider && header.keyVersion == currentEpoch;
}

// ── records.cpp ─────────────────────────────────────────────────────────────────────────────────────

static Path patient(const core::Buffer& patientId) { return {name("clinic"), name("patient"), id(patientId)}; }
static Path billing() { return {name("clinic"), name("billing")}; }

static core::Buffer saveDischarge(
    GroupHandle& team, const core::Buffer& dischargeId, const std::string& billingOwner,
    const core::UserWithPubKey& auditor, const std::string& text
) {
    EncryptOptions options;
    // Billing is named, not given as a key: its current key is fetched at every encryption.
    options.alsoFor.push_back({.groupId = {}, .groupSubject = billing(), .groupCreatedBy = billingOwner, .user = std::nullopt});
    options.alsoFor.push_back({.groupId = {}, .groupSubject = {}, .groupCreatedBy = {}, .user = auditor});
    return team.encrypt({name("discharge"), id(dischargeId)}, core::Buffer::from(text), options);
}

// Billing and the auditor read it with the same call: the library finds the caller among the recipients.
static DecryptedSharedEnvelope readSharedDischarge(
    GroupClient& groups,
    const core::Buffer& patientId,
    const core::Buffer& dischargeId,
    const std::string& authorId,
    const core::Buffer& body
) {
    return groups.decryptShared(patient(patientId), {name("discharge"), id(dischargeId)}, body, by(authorId));
}

// Runs on the analyzer: an account in the Context, a member of no care team.
static core::Buffer sendLabResult(
    GroupClient& analyzerGroups, const core::Buffer& patientId, const std::string& doctorId,
    const core::Buffer& resultId, const std::string& result
) {
    GroupOutsider outsider = analyzerGroups.openForWriting(patient(patientId), doctorId); // writes only: there is no decrypt on it
    return outsider.encrypt({name("lab"), id(resultId)}, core::Buffer::from(result));
}

// Runs in the care team. An unsigned result does not get this far: decryptFromOutsider reads signed ones only.
static std::string readLabResult(GroupHandle& team, const core::Buffer& resultId, const core::Buffer& body) {
    DecryptedOutsiderEnvelope result = team.decryptFromOutsider({name("lab"), id(resultId)}, body, anyAuthor());
    return result.sender.userId + ": " + result.data.stdString();
}

static std::vector<core::Buffer> writeEdits(GroupHandle& doc, const core::Buffer& sequenceId, const std::vector<std::string>& edits) {
    GroupSequenceWriter ops = doc.beginSequence({name("ops"), id(sequenceId)}, 2);
    std::vector<core::Buffer> wire{ops.getHeader()};
    for (const auto& edit : edits) {
        SequenceAppendResult appended = ops.append(core::Buffer::from(edit)); // throws after a removal
        wire.push_back(appended.item);
        if (appended.mark.has_value()) {
            wire.push_back(appended.mark.value());
        }
    }
    wire.push_back(ops.finish());
    return wire;
}

static std::vector<std::string> readEdits(
    GroupHandle& doc, const core::Buffer& sequenceId, const std::string& authorId, const std::vector<core::Buffer>& wire,
    SequenceMarkInfo& mark
) {
    GroupSequenceReader ops = doc.openSequence({name("ops"), id(sequenceId)}, wire.front(), by(authorId));
    std::vector<std::string> edits;
    for (std::size_t i = 1; i < wire.size(); ++i) {
        if (GroupApi::peekSequenceItem(wire[i]).isMark) {
            mark = ops.verify(wire[i]);
        } else {
            edits.push_back(ops.read(wire[i]).data.stdString()); // item.missing: edits that never arrived
        }
    }
    ops.close();
    return edits;
}

// ── space.cpp ───────────────────────────────────────────────────────────────────────────────────────

static Path project(const std::string& projectId) { return {name("crm"), name("project"), id(projectId)}; }
static Path team(const std::string& teamId) { return {name("crm"), name("team"), id(teamId)}; }

// The Space's key is wrapped once for each team, here and never again until the key is replaced.
static Space createProjectSpace(
    GroupClient& groups, const std::string& projectId, const std::string& salesId, const std::string& salesOwner,
    const std::string& supportId, const std::string& supportOwner
) {
    return groups.createSpaceFor(
        project(projectId),
        {
            {.groupId = {}, .groupSubject = team(salesId), .groupCreatedBy = salesOwner, .user = std::nullopt, .role = "manager"},
            {.groupId = {}, .groupSubject = team(supportId), .groupCreatedBy = supportOwner, .user = std::nullopt, .role = "user"},
        },
        {},
        {}
    );
}

// Nothing is wrapped: one symmetric encryption and one signature per note.
static core::Buffer saveNote(Space& projectSpace, const std::string& noteId, const std::string& text) {
    return projectSpace.encrypt({name("note"), id(noteId), name("rev"), name("1")}, core::Buffer::from(text));
}

static std::string readNote(
    GroupClient& groups,
    const std::string& projectId,
    const std::string& ownerId,
    const std::string& noteId,
    const std::string& authorId,
    const core::Buffer& body
) {
    Space projectSpace = groups.openSpace(project(projectId), {.createdBy = ownerId});
    DecryptedSpaceEnvelope note =
        projectSpace.decrypt({name("note"), id(noteId), name("rev"), name("1")}, body, by(authorId));
    // The key alone does not say the author still had access: someone removed from a team keeps the Space's
    // key until it is replaced.
    if (note.origin.authorAccess != "yes") {
        throw std::string("written by someone whose access is not confirmed");
    }
    return note.data.stdString();
}

// Removing someone from a team does not touch the Space: they still hold its key. Replace it at once.
static void removeFromTeam(GroupClient& groups, Space& projectSpace, const std::string& salesId, const std::string& userId) {
    GroupHandle salesGroup = groups.openGroup(team(salesId));
    salesGroup.removeMembers({userId});
    if (projectSpace.getState().keyIsStale) {
        projectSpace.rotateKey();
    }
}

// ── the tests ───────────────────────────────────────────────────────────────────────────────────────

class GroupClientTest : public privmx::test::BaseGroupTest {
protected:
    GroupClient groups;
    void setUpModuleApis() override { groups = GroupClient::create(*groupApi, contextId()); }
    void switchTo(int index) {
        disconnect();
        connectAs(index);
    }
    GroupMemberToAdd member(int index, const std::string& role) { return GroupMemberToAdd{.user = user(index), .role = role}; }
    // Fresh for every test run: a subject has one Group for good.
    std::string fresh(const std::string& what) { return what + "-" + freshUuid(); }
    static std::string freshUuid() {
        static int counter = 0;
        char buffer[64];
        std::snprintf(buffer, sizeof(buffer), "6f9619ff-8b86-d011-b42d-%012llx",
                      static_cast<unsigned long long>(std::chrono::steady_clock::now().time_since_epoch().count() + counter++) & 0xffffffffffffULL);
        return buffer;
    }
};

TEST_F(GroupClientTest, chat_a_group_made_with_its_entity_is_opened_by_subject_and_creator) {
    CreatedGroup created = createChat(groups, {member(1, "manager"), member(2, "user"), member(3, "user")});
    const Path subject = created.group.getSubject();
    ASSERT_EQ(subject.size(), 3u);
    EXPECT_TRUE(subject.back().isId);
    EXPECT_EQ(subject.back().value.stdString(), created.id.stdString());
    EXPECT_EQ(created.group.getGroupId(), groups.groupIdOf(subject));

    const core::Buffer m1 = GroupApi::idFromString("m1"), m2 = GroupApi::idFromString("m2");
    const core::Buffer first = sendMessage(created.group, m1, "hello");
    EXPECT_TRUE(mayStore(first, created.group.getGroupId(), 1));
    // The same subject a second time: somebody has made its Group, and it was not this call.
    EXPECT_THROW(
        { groups.createGroupFor(subject, {member(1, "manager")}, {}, {}); }, GroupAlreadyExistsException
    );
    // A place is said: every value of the chat would otherwise sit at the same spot.
    EXPECT_THROW({ created.group.encrypt(GroupApi::noLocation(), core::Buffer::from("x")); }, core::InvalidParamsException);
    EXPECT_THROW({ created.group.encrypt({}, core::Buffer::from("x")); }, core::InvalidParamsException);

    switchTo(2);
    GroupHandle chat = groups.openGroup(subject, {.createdBy = userId(1)});
    EXPECT_EQ(chat.getGroupId(), created.group.getGroupId());
    EXPECT_EQ(chat.getState().privateMeta.stdString(), "Design");
    const core::Buffer second = sendMessage(chat, m2, "hi back");
    const std::vector<std::string> shown = loadMessages(
        chat,
        {
            {.messageId = m1, .authorId = userId(1), .body = first},
            {.messageId = m2, .authorId = userId(2), .body = second},
            {.messageId = m2, .authorId = userId(1), .body = second}, // the server names another author
            {.messageId = m2, .authorId = userId(1), .body = first},  // and puts one message in another's row
        }
    );
    EXPECT_EQ(shown, (std::vector<std::string>{"hello", "hi back", "message could not be verified", "message could not be verified"}));
    // The creator is the signer of the Group's first statement: somebody else's Group under this subject is refused.
    EXPECT_THROW({ groups.openGroup(subject, {.createdBy = userId(3)}); }, GroupWrongCreatorException);
    // A message of this chat does not open as one of another chat with the same members.
    CreatedGroup other = createChat(groups, {member(2, "manager"), member(1, "user")});
    EXPECT_ANY_THROW({ other.group.decrypt({name("message"), id(m1), name("body")}, first, anyAuthor()); });

    switchTo(1);
    GroupHandle mine = groups.openGroup(subject, {.createdBy = userId(1)});
    EXPECT_EQ(mine.removeMembers({userId(3)}), 2);
    EXPECT_FALSE(mayStore(first, mine.getGroupId(), 2));
    EXPECT_EQ(mine.getLog(core::PagingQuery{.skip = 0, .limit = 10, .sortOrder = "asc"}).readItems.size(), 2u);
}

TEST_F(GroupClientTest, chat_a_direct_chat_is_a_fixed_group_of_exactly_its_two_users) {
    // The subject is the two users: either of them, or anyone, can compute it - and make a Group under it first.
    const Path subject = directSubject(userId(1), userId(2));
    try {
        groups.createFixedGroup(subject, {user(1), user(2)}, {}, core::Buffer::from("dm"));
    } catch (const GroupAlreadyExistsException&) {} // an earlier run of this test on the same Bridge
    GroupHandle dm = openDirect(groups, userId(1), userId(2));
    const core::Buffer sealed = sendMessage(dm, GroupApi::idFromString("m1"), "just us");

    // Opened only by naming exactly its members; a subject-and-creator open is not for a fixed Group.
    EXPECT_THROW({ groups.openFixedGroup(subject, {userId(1), userId(3)}); }, GroupMembershipMismatchException);
    EXPECT_THROW({ groups.openFixedGroup(subject, {userId(1)}); }, GroupMembershipMismatchException);
    EXPECT_THROW({ groups.openGroup(subject); }, GroupMembershipMismatchException);
    // Frozen: nobody is added or removed, and the rules that say so cannot be changed.
    EXPECT_ANY_THROW({ dm.addMembers({member(3, "user")}); });
    EXPECT_ANY_THROW({ dm.removeMembers({userId(2)}); });
    EXPECT_ANY_THROW({ dm.updateRules(GroupRulesUpdate{.addMembers = "user", .removeMembers = std::nullopt, .updateMeta = std::nullopt}); });

    switchTo(2);
    GroupHandle theirs = openDirect(groups, userId(2), userId(1));
    EXPECT_EQ(theirs.decrypt({name("message"), id(GroupApi::idFromString("m1")), name("body")}, sealed, by(userId(1))).data.stdString(), "just us");

    // A Group that only looks like the chat: user 3 makes an ordinary Group with user 1 under a subject of two
    // other users. Whoever opens that chat names its members, and gets a refusal.
    switchTo(3);
    const Path forged = directSubject(userId(1), fresh("nobody"));
    GroupHandle trap = groups.createGroupFor(forged, {member(3, "manager"), member(1, "user")}, {}, {});
    switchTo(1);
    EXPECT_THROW({ groups.openFixedGroup(forged, {userId(1), userId(2)}); }, GroupMembershipMismatchException);
    EXPECT_EQ(groups.openGroup(forged).getGroupId(), trap.getGroupId());
}

TEST_F(GroupClientTest, many_groups_open_with_one_read_and_a_group_with_its_own_id_is_pinned_to_its_subject) {
    CreatedGroup a = createChat(groups, {member(1, "manager"), member(2, "user")});
    CreatedGroup b = createChat(groups, {member(1, "manager")});
    const std::string legacyId = groupApi->createGroup(contextId(), {user(2)}, {user(1)}, {}, {});
    const std::string otherId = groupApi->createGroup(contextId(), {}, {user(1)}, {}, {});
    const Path legacy = {name("chat-app"), name("room"), id(fresh("room"))};
    const Path missing = {name("chat-app"), name("chat"), id(fresh("never-made"))};

    const std::vector<OpenGroupResult> opened = groups.openGroups({
        {.subject = a.group.getSubject(), .createdBy = userId(1), .fixedMembers = {}, .pinnedGroupId = {}},
        {.subject = b.group.getSubject(), .createdBy = userId(2), .fixedMembers = {}, .pinnedGroupId = {}},
        {.subject = legacy, .createdBy = {}, .fixedMembers = {}, .pinnedGroupId = legacyId},
        {.subject = missing, .createdBy = {}, .fixedMembers = {}, .pinnedGroupId = {}},
        {.subject = a.group.getSubject(), .createdBy = {}, .fixedMembers = std::vector<std::string>{userId(1), userId(2)}, .pinnedGroupId = {}},
    });
    ASSERT_EQ(opened.size(), 5u);
    EXPECT_EQ(opened[0].statusCode, 0);
    EXPECT_EQ(opened[0].group.getGroupId(), a.group.getGroupId());
    EXPECT_EQ(opened[1].statusCode, static_cast<int64_t>(GroupWrongCreatorException::FULL_CODE));
    EXPECT_EQ(opened[2].statusCode, 0);
    EXPECT_EQ(opened[2].group.getGroupId(), legacyId);
    EXPECT_NE(opened[3].statusCode, 0);
    EXPECT_EQ(opened[4].statusCode, static_cast<int64_t>(GroupMembershipMismatchException::FULL_CODE));

    // The pinned Group writes at subject + place like any other, and this device keeps it for that subject.
    GroupHandle room = groups.openPinnedGroup(legacy, legacyId);
    const core::Buffer sealed = room.encrypt({name("message"), id("m1")}, core::Buffer::from("old room"));
    EXPECT_TRUE(GroupApi::peekEnvelope(sealed).hasLocation);
    EXPECT_THROW({ groups.openPinnedGroup(legacy, otherId); }, GroupSubjectReboundException);
    EXPECT_NO_THROW({ groups.openPinnedGroup(legacy, legacyId); });
    switchTo(2);
    EXPECT_EQ(groups.openPinnedGroup(legacy, legacyId).decrypt({name("message"), id("m1")}, sealed, by(userId(1))).data.stdString(), "old room");

    // No entity at all: the ID is the application's to keep, and a location is whole or said to be none.
    switchTo(1);
    GroupHandle unbound = groups.createUnboundGroup({member(1, "manager"), member(2, "user")}, {}, {});
    EXPECT_TRUE(unbound.getSubject().empty());
    const core::Buffer plain = unbound.encrypt(GroupApi::noLocation(), core::Buffer::from("room talk"));
    EXPECT_FALSE(GroupApi::peekEnvelope(plain).hasLocation);
    EXPECT_EQ(groups.openUnboundGroup(unbound.getGroupId()).decrypt(GroupApi::noLocation(), plain, by(userId(1))).data.stdString(), "room talk");
}

TEST_F(GroupClientTest, records_three_audiences_a_writer_that_cannot_read_and_a_sequence) {
    const core::Buffer patientId = GroupApi::idFromString(fresh("patient"));
    const core::Buffer dischargeId = GroupApi::idFromString("d1"), resultId = GroupApi::idFromString("r1");
    GroupHandle care = groups.createGroupFor(patient(patientId), {member(1, "manager")}, {}, {}, std::nullopt, "context");
    switchTo(2);
    GroupHandle billingGroup;
    try {
        billingGroup = groups.createGroupFor(billing(), {member(2, "manager")}, {}, {}, std::nullopt, "context");
    } catch (const GroupAlreadyExistsException&) { billingGroup = groups.openGroup(billing()); }

    switchTo(1);
    care = groups.openGroup(patient(patientId), {.createdBy = userId(1)});
    // Billing is named with who made it: wrapped for a Group somebody else put under that name, the summary
    // would be theirs to read.
    EXPECT_THROW({ saveDischarge(care, dischargeId, userId(3), user(3), "x"); }, GroupWrongCreatorException);
    EXPECT_THROW({ saveDischarge(care, dischargeId, "", user(3), "x"); }, core::InvalidParamsException);
    const core::Buffer discharge = saveDischarge(care, dischargeId, userId(2), user(3), "discharged, stable");
    // The care team reads it as its own; billing (user 2) and the auditor (user 3) as shared with them.
    EXPECT_EQ(care.decrypt({name("discharge"), id(dischargeId)}, discharge, by(userId(1))).data.stdString(), "discharged, stable");
    EXPECT_THROW({ readSharedDischarge(groups, patientId, dischargeId, userId(1), discharge); }, EnvelopeNotARecipientException);

    switchTo(2);
    DecryptedSharedEnvelope shared = readSharedDischarge(groups, patientId, dischargeId, userId(1), discharge);
    EXPECT_EQ(shared.data.stdString(), "discharged, stable");
    EXPECT_EQ(shared.via, billingGroup.getGroupId());
    EXPECT_EQ(shared.homeGroupId, care.getGroupId());
    EXPECT_EQ(shared.senderMembership, "member"); // the care team is visible to the Context
    // The same envelope presented as another patient's: it says which Group it was written in.
    EXPECT_THROW(
        { groups.decryptShared(patient(GroupApi::idFromString("someone-else")), {name("discharge"), id(dischargeId)}, discharge, by(userId(1))); },
        EnvelopeWrongGroupException
    );
    EXPECT_THROW(
        { groups.decryptShared(patient(patientId), {name("discharge"), id(dischargeId)}, discharge, by(userId(1)), {.createdBy = userId(3)}); },
        GroupWrongCreatorException
    );
    // A Group named by its subject is named with its creator: user 3 could have made "this patient's team" first.
    EXPECT_THROW({ groups.openForWriting(patient(patientId), userId(3)); }, GroupWrongCreatorException);
    EXPECT_THROW({ groups.openForWriting(patient(patientId), ""); }, core::InvalidParamsException);
    EXPECT_THROW({ groups.getPublicKey(patient(patientId), userId(3)); }, GroupWrongCreatorException);
    // The analyzer: a writer that cannot read, not even its own result.
    const core::Buffer lab = sendLabResult(groups, patientId, userId(1), resultId, "CRP 3.1");
    EXPECT_ANY_THROW({ groups.openGroup(patient(patientId)); });

    switchTo(3);
    shared = readSharedDischarge(groups, patientId, dischargeId, userId(1), discharge);
    EXPECT_EQ(shared.via, "user");
    // A public form: a key the team published, and no account behind the writer.
    const GroupPublicKey published = groups.getPublicKey(patient(patientId), userId(1));
    const core::Buffer intake =
        GroupOutsider::anonymous(*groupApi, published, patient(patientId)).encrypt({name("intake"), id("i1")}, core::Buffer::from("form"));

    switchTo(1);
    care = groups.openGroup(patient(patientId), {.createdBy = userId(1)});
    EXPECT_EQ(readLabResult(care, resultId, lab), userId(2) + ": CRP 3.1");
    EXPECT_THROW({ care.decrypt({name("lab"), id(resultId)}, lab, anyAuthor()); }, EnvelopeWrongKindException);
    EXPECT_EQ(care.decryptAnonymous({name("intake"), id("i1")}, intake).data.stdString(), "form");
    EXPECT_THROW({ care.decryptFromOutsider({name("intake"), id("i1")}, intake, anyAuthor()); }, EnvelopeWrongKindException);

    // A sequence of edits, and a file, by place.
    const core::Buffer sequenceId = GroupApi::idFromString("s1");
    const std::vector<core::Buffer> wire = writeEdits(care, sequenceId, {"a", "b", "c"});
    SequenceMarkInfo mark{};
    EXPECT_EQ(readEdits(care, sequenceId, userId(1), wire, mark), (std::vector<std::string>{"a", "b", "c"}));
    EXPECT_EQ(mark.attestedItems, 3);
    EXPECT_TRUE(mark.closed);
    GroupFileWriter writer = care.beginFileEncryption({name("scan"), id("x1")});
    const core::Buffer cipher = writer.encryptChunk(core::Buffer::from(std::string(5000, 's')));
    const core::Buffer fileEnvelope = writer.finish();
    GroupFileReader reader = care.beginFileDecryption({name("scan"), id("x1")}, fileEnvelope, by(userId(1)));
    EXPECT_EQ(reader.getCipherRange(0, 5000).length, static_cast<int64_t>(cipher.size()));
    EXPECT_EQ(reader.decryptChunk(cipher).stdString(), std::string(5000, 's'));
    EXPECT_TRUE(reader.finish().complete);
    EXPECT_THROW({ care.beginFileDecryption({name("scan"), id("x2")}, fileEnvelope, by(userId(1))); }, EnvelopeWrongLocationException);
}

TEST_F(GroupClientTest, space_one_key_for_two_teams_named_by_their_subjects) {
    const std::string projectId = fresh("project"), salesId = fresh("sales"), supportId = fresh("support");
    groups.createGroupFor(team(salesId), {member(1, "manager"), member(2, "user")}, {}, {}, std::nullopt, "context");
    switchTo(3);
    groups.createGroupFor(team(supportId), {member(3, "manager")}, {}, {}, std::nullopt, "context");
    switchTo(1);

    EXPECT_THROW({ createProjectSpace(groups, projectId, salesId, userId(1), supportId, userId(2)); }, GroupWrongCreatorException);
    Space projectSpace = createProjectSpace(groups, projectId, salesId, userId(1), supportId, userId(3));
    EXPECT_EQ(projectSpace.getSpaceId(), GroupApi::deriveSpaceId(contextId(), GroupApi::encodePath(project(projectId))));
    EXPECT_THROW({ createProjectSpace(groups, projectId, salesId, userId(1), supportId, userId(3)); }, GroupAlreadyExistsException);
    const core::Buffer note = saveNote(projectSpace, "n1", "call the client");

    switchTo(3);
    EXPECT_THROW({ readNote(groups, projectId, userId(3), "n1", userId(1), note); }, GroupWrongCreatorException);
    // Support cannot see the roster of sales: the note opens, and its author's access is "unknown" - not "yes".
    Space theirs = groups.openSpace(project(projectId), {.createdBy = userId(1)});
    DecryptedSpaceEnvelope opened = theirs.decrypt({name("note"), id("n1"), name("rev"), name("1")}, note, by(userId(1)));
    EXPECT_EQ(opened.data.stdString(), "call the client");
    switchTo(2);
    EXPECT_EQ(readNote(groups, projectId, userId(1), "n1", userId(1), note), "call the client");
    Space asUser2 = groups.openSpace(project(projectId));
    const core::Buffer byUser2 = saveNote(asUser2, "n2", "sent the offer");

    switchTo(1);
    projectSpace = groups.openSpace(project(projectId), {.createdBy = userId(1)});
    EXPECT_EQ(readNote(groups, projectId, userId(1), "n2", userId(2), byUser2), "sent the offer");
    removeFromTeam(groups, projectSpace, salesId, userId(2));
    const SpaceState state = projectSpace.getState();
    EXPECT_EQ(state.keyVersion, 2);
    EXPECT_FALSE(state.keyIsStale);
    // What user 2 wrote still opens; that they are no longer on the team is said, and the example refuses it.
    EXPECT_THROW({ readNote(groups, projectId, userId(1), "n2", userId(2), byUser2); }, std::string);
    const core::Buffer after = saveNote(projectSpace, "n3", "new terms");

    // changeTeams: support leaves by its subject, and a user joins who reads what is already there.
    EXPECT_EQ(projectSpace.removeRecipients({{.groupId = {}, .groupSubject = team(supportId), .userId = {}}}), 3);
    projectSpace.addRecipients({{.groupId = {}, .groupSubject = {}, .groupCreatedBy = {}, .user = user(2), .role = "user"}});
    switchTo(2);
    EXPECT_EQ(groups.openSpace(project(projectId)).decrypt({name("note"), id("n3"), name("rev"), name("1")}, after, by(userId(1))).data.stdString(), "new terms");
    switchTo(3);
    EXPECT_ANY_THROW({ groups.openSpace(project(projectId)); });

    // A Space bound to no entity: a full location, or none.
    switchTo(1);
    Space unbound = groups.createUnboundSpace({{.groupId = {}, .groupSubject = {}, .groupCreatedBy = {}, .user = user(1), .role = "manager"}}, {}, {});
    const core::Buffer plain = unbound.encrypt(GroupApi::noLocation(), core::Buffer::from("x"));
    EXPECT_EQ(groups.openUnboundSpace(unbound.getSpaceId()).decrypt(GroupApi::noLocation(), plain, by(userId(1))).data.stdString(), "x");
}
