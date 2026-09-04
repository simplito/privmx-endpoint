#include <gtest/gtest.h>
#include "../../utils/BaseTest.hpp"
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/group/GroupApi.hpp>
#include <privmx/endpoint/group/VarSerializer.hpp>
#include <privmx/endpoint/core/CoreException.hpp>

using namespace privmx::endpoint;

enum GroupConnectionType {
    GUser1,
    GUser2
};

class GroupTest : public privmx::test::BaseTest {
protected:
    GroupTest() : BaseTest(privmx::test::BaseTestMode::online) {}
    void connectAs(GroupConnectionType type) {
        if (type == GroupConnectionType::GUser1) {
            connection = std::make_shared<core::Connection>(
                core::Connection::connect(
                    reader->getString("Login.user_1_privKey"),
                    reader->getString("Login.solutionId"),
                    getPlatformUrl(reader->getString("Login.instanceUrl"))
                )
            );
        } else {
            connection = std::make_shared<core::Connection>(
                core::Connection::connect(
                    reader->getString("Login.user_2_privKey"),
                    reader->getString("Login.solutionId"),
                    getPlatformUrl(reader->getString("Login.instanceUrl"))
                )
            );
        }
        groupApi = std::make_shared<group::GroupApi>(group::GroupApi::create(*connection));
    }
    void disconnect() {
        connection->disconnect();
        connection.reset();
        groupApi.reset();
    }
    void customSetUp() override {
        reader = new Poco::Util::IniFileConfiguration(INI_FILE_PATH);
        connection = std::make_shared<core::Connection>(
            core::Connection::connect(
                reader->getString("Login.user_1_privKey"),
                reader->getString("Login.solutionId"),
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
        groupApi = std::make_shared<group::GroupApi>(group::GroupApi::create(*connection));
    }
    void customTearDown() override {
        connection.reset();
        groupApi.reset();
        reader.reset();
        core::EventQueueImpl::getInstance()->clear();
    }
    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<group::GroupApi> groupApi;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};

TEST_F(GroupTest, setup) {
}

TEST_F(GroupTest, getGroup) {
    group::Group group;
    // incorrect groupId
    EXPECT_THROW({
        groupApi->getGroup(reader->getString("Context_1.contextId"));
    }, core::Exception);
    // correct groupId
    EXPECT_NO_THROW({
        group = groupApi->getGroup(reader->getString("Group_1.groupId"));
    });
    EXPECT_EQ(group.contextId, reader->getString("Group_1.contextId"));
    EXPECT_EQ(group.groupId, reader->getString("Group_1.groupId"));
    EXPECT_NE(group.groupPubKey, "");
    EXPECT_EQ(group.createDate, reader->getInt64("Group_1.createDate"));
    EXPECT_EQ(group.creator, reader->getString("Group_1.creator"));
    EXPECT_EQ(group.lastModificationDate, reader->getInt64("Group_1.lastModificationDate"));
    EXPECT_EQ(group.lastModifier, reader->getString("Group_1.lastModifier"));
    EXPECT_EQ(group.version, reader->getInt64("Group_1.version"));
    EXPECT_EQ(group.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Group_1.publicMeta_inHex")));
    EXPECT_EQ(group.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Group_1.privateMeta_inHex")));
    EXPECT_EQ(group.statusCode, 0);
    EXPECT_EQ(group.users.size(), 1);
    if (group.users.size() == 1) {
        EXPECT_EQ(group.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(group.managers.size(), 1);
    if (group.managers.size() == 1) {
        EXPECT_EQ(group.managers[0], reader->getString("Login.user_1_id"));
    }
}

TEST_F(GroupTest, listGroups_incorrect_input_data) {
    // incorrect contextId
    EXPECT_THROW({
        groupApi->listGroups(
            reader->getString("Group_1.groupId"),
            core::PagingQuery{.skip = 0, .limit = 10, .sortOrder = "asc"}
        );
    }, core::Exception);
    // invalid sortOrder
    EXPECT_THROW({
        groupApi->listGroups(
            reader->getString("Context_1.contextId"),
            core::PagingQuery{.skip = 0, .limit = 10, .sortOrder = "bad_sort_order"}
        );
    }, core::Exception);
}

TEST_F(GroupTest, listGroups_correct_input_data) {
    core::PagingList<group::GroupSummary> groupsList;
    EXPECT_NO_THROW({
        groupsList = groupApi->listGroups(
            reader->getString("Context_1.contextId"),
            core::PagingQuery{.skip = 0, .limit = 10, .sortOrder = "asc"}
        );
    });
    // pre-created at least 2
    EXPECT_GE(groupsList.totalAvailable, 2);
    EXPECT_GE(groupsList.readItems.size(), 2);
    for (const auto& g : groupsList.readItems) {
        EXPECT_EQ(g.contextId, reader->getString("Context_1.contextId"));
        EXPECT_FALSE(g.groupId.empty());
        EXPECT_FALSE(g.groupPubKey.empty());
        EXPECT_GE(g.keyVersion, 0);
    }
    // limit=1
    core::PagingList<group::GroupSummary> groupsPage;
    EXPECT_NO_THROW({
        groupsPage = groupApi->listGroups(
            reader->getString("Context_1.contextId"),
            core::PagingQuery{.skip = 0, .limit = 1, .sortOrder = "asc"}
        );
    });
    EXPECT_GE(groupsPage.totalAvailable, 2);
    EXPECT_EQ(groupsPage.readItems.size(), 1);
}


TEST_F(GroupTest, createGroup_incorrect_data) {
    // incorrect contextId
    EXPECT_THROW({
        groupApi->createGroup(
            reader->getString("Group_1.groupId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private")
        );
    }, core::Exception);
    // user pubKey mismatch
    EXPECT_THROW({
        groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_2_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private")
        );
    }, core::Exception);
    // manager pubKey mismatch
    EXPECT_THROW({
        groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_2_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private")
        );
    }, core::Exception);
    // no managers
    EXPECT_THROW({
        groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{},
            core::Buffer::from("public"),
            core::Buffer::from("private")
        );
    }, core::Exception);
}

TEST_F(GroupTest, createGroup) {
    std::string groupId;
    group::Group group;
    // different users and managers
    EXPECT_NO_THROW({
        groupId = groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_2_id"),
                .pubKey = reader->getString("Login.user_2_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private")
        );
    });
    ASSERT_FALSE(groupId.empty());
    EXPECT_NO_THROW({
        group = groupApi->getGroup(groupId);
    });
    EXPECT_EQ(group.statusCode, 0);
    EXPECT_EQ(group.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(group.publicMeta.stdString(), "public");
    EXPECT_EQ(group.privateMeta.stdString(), "private");
    EXPECT_EQ(group.version, 1);
    EXPECT_NE(group.groupPubKey, "");
    EXPECT_EQ(group.users.size(), 1);
    if (group.users.size() == 1) {
        EXPECT_EQ(group.users[0], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(group.managers.size(), 1);
    if (group.managers.size() == 1) {
        EXPECT_EQ(group.managers[0], reader->getString("Login.user_1_id"));
    }
    // same users and managers
    EXPECT_NO_THROW({
        groupId = groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("public2"),
            core::Buffer::from("private2")
        );
    });
    ASSERT_FALSE(groupId.empty());
    EXPECT_NO_THROW({
        group = groupApi->getGroup(groupId);
    });
    EXPECT_EQ(group.statusCode, 0);
    EXPECT_EQ(group.publicMeta.stdString(), "public2");
    EXPECT_EQ(group.privateMeta.stdString(), "private2");
    EXPECT_EQ(group.version, 1);
}

TEST_F(GroupTest, updateGroup_incorrect_data) {
    // incorrect groupId
    EXPECT_THROW({
        groupApi->updateGroup(
            reader->getString("Context_1.contextId"),
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1,
            false,
            false
        );
    }, core::Exception);
    // wrong version, force=false
    EXPECT_THROW({
        groupApi->updateGroup(
            reader->getString("Group_2.groupId"),
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            99,
            false,
            false
        );
    }, core::Exception);
}

TEST_F(GroupTest, updateGroup_correct_data) {
    group::Group group;
    EXPECT_NO_THROW({
        groupApi->updateGroup(
            reader->getString("Group_1.groupId"),
            core::Buffer::from("updated_public"),
            core::Buffer::from("updated_private"),
            1,
            false,
            false
        );
    });
    EXPECT_NO_THROW({
        group = groupApi->getGroup(reader->getString("Group_1.groupId"));
    });
    EXPECT_EQ(group.statusCode, 0);
    EXPECT_EQ(group.version, 2);
    EXPECT_EQ(group.publicMeta.stdString(), "updated_public");
    EXPECT_EQ(group.privateMeta.stdString(), "updated_private");
    EXPECT_EQ(group.users.size(), 1);
    EXPECT_EQ(group.managers.size(), 1);
    if (group.managers.size() == 1) {
        EXPECT_EQ(group.managers[0], reader->getString("Login.user_1_id"));
    }
    // A second metadata update, and the roster is still the one the group was created with: updateGroup cannot
    // reach it at all any more. Promoting somebody goes through addGroupMembers/removeGroupMembers.
    EXPECT_NO_THROW({
        groupApi->updateGroup(
            reader->getString("Group_1.groupId"),
            core::Buffer::from("updated_public_2"),
            core::Buffer::from("updated_private_2"),
            2,
            false,
            false
        );
    });
    EXPECT_NO_THROW({
        group = groupApi->getGroup(reader->getString("Group_1.groupId"));
    });
    EXPECT_EQ(group.statusCode, 0);
    EXPECT_EQ(group.version, 3);
    EXPECT_EQ(group.publicMeta.stdString(), "updated_public_2");
    EXPECT_EQ(group.privateMeta.stdString(), "updated_private_2");
    EXPECT_EQ(group.users.size(), 1);
    EXPECT_EQ(group.managers.size(), 1);
}

TEST_F(GroupTest, updateGroup_chain_integrity) {
    // A three-entry group (create + 2 updates) must pass G1/G2 → statusCode=0
    std::string groupId;
    EXPECT_NO_THROW({
        groupId = groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("v1"),
            core::Buffer::from("v1_priv")
        );
    });
    ASSERT_FALSE(groupId.empty());
    // update v1→v2
    EXPECT_NO_THROW({
        groupApi->updateGroup(
            groupId,
            core::Buffer::from("v2"),
            core::Buffer::from("v2_priv"),
            1,
            false,
            false
        );
    });
    // update v2→v3
    EXPECT_NO_THROW({
        groupApi->updateGroup(
            groupId,
            core::Buffer::from("v3"),
            core::Buffer::from("v3_priv"),
            2,
            false,
            false
        );
    });
    group::Group group;
    EXPECT_NO_THROW({
        group = groupApi->getGroup(groupId);
    });
    EXPECT_EQ(group.version, 3);
    EXPECT_EQ(group.statusCode, 0);
    EXPECT_EQ(group.publicMeta.stdString(), "v3");
    EXPECT_EQ(group.privateMeta.stdString(), "v3_priv");
}

TEST_F(GroupTest, updateGroup_force) {
    group::Group group;
    EXPECT_NO_THROW({
        groupApi->updateGroup(
            reader->getString("Group_2.groupId"),
            core::Buffer::from("forced"),
            core::Buffer::from("forced_priv"),
            99,
            true,
            false
        );
    });
    EXPECT_NO_THROW({
        group = groupApi->getGroup(reader->getString("Group_2.groupId"));
    });
    EXPECT_EQ(group.statusCode, 0);
    EXPECT_EQ(group.publicMeta.stdString(), "forced");
}

TEST_F(GroupTest, deleteGroup) {
    std::string groupId = reader->getString("Group_1.groupId");
    EXPECT_NO_THROW({
        groupApi->deleteGroup(groupId);
    });
    // group no longer accessible after delete
    EXPECT_THROW({
        groupApi->getGroup(groupId);
    }, core::Exception);
    // deleting a non-existent groupId
    EXPECT_THROW({
        groupApi->deleteGroup(reader->getString("Context_1.contextId"));
    }, core::Exception);
}

TEST_F(GroupTest, group_member_can_read) {
    // Create group with user_1 as manager, user_2 as member
    std::string groupId;
    EXPECT_NO_THROW({
        groupId = groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId = reader->getString("Login.user_1_id"),
                    .pubKey = reader->getString("Login.user_1_pubKey")
                },
                core::UserWithPubKey{
                    .userId = reader->getString("Login.user_2_id"),
                    .pubKey = reader->getString("Login.user_2_pubKey")
                }
            },
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("shared_public"),
            core::Buffer::from("shared_private")
        );
    });
    ASSERT_FALSE(groupId.empty());
    // Connect as user_2 (member, not manager) and read the group
    disconnect();
    connectAs(GroupConnectionType::GUser2);
    group::Group group;
    EXPECT_NO_THROW({
        group = groupApi->getGroup(groupId);
    });
    EXPECT_EQ(group.statusCode, 0);
    EXPECT_EQ(group.publicMeta.stdString(), "shared_public");
    EXPECT_EQ(group.privateMeta.stdString(), "shared_private");
    EXPECT_EQ(group.groupId, groupId);
}

// -- the objects the documented examples talk to ------------------------------------------------------
//
// GroupApi.hpp documents the file API with three worked examples, and the tests below paste those examples
// in unchanged rather than paraphrasing them. That is the point: a snippet that drifts from the API stops
// compiling here, so the documentation cannot quietly rot into something that no longer works.
//
// These three types exist only to give the snippets something to read from and write to. They are as small
// as they can be while still being the shapes the examples name: a plaintext source, a sink, and ciphertext
// storage that can be read sequentially or at an offset.

struct ByteSource {
    std::string data;
    std::size_t pos = 0;
    bool hasMore() const { return pos < data.size(); }
    core::Buffer read(std::size_t n) {
        std::string out = data.substr(pos, n);
        pos += out.size();
        return core::Buffer::from(out);
    }
};

struct ByteSink {
    std::string data;
    void write(const core::Buffer& block) { data.append(block.stdString()); }
};

struct CipherStorage {
    std::string data;
    std::size_t pos = 0;
    bool hasMore() const { return pos < data.size(); }
    /** Sequential, as the opening example uses it. */
    core::Buffer read(std::size_t n) {
        std::string out = data.substr(pos, n);
        pos += out.size();
        return core::Buffer::from(out);
    }
    /** Random access, as the range example uses it. */
    core::Buffer read(std::size_t offset, std::size_t n) const {
        return core::Buffer::from(offset >= data.size() ? std::string() : data.substr(offset, n));
    }
};

// -- envelopes -----------------------------------------------------------------------------------------

TEST_F(GroupTest, envelope_roundtrip_between_members) {
    std::string groupId = groupApi->createGroup(
        reader->getString("Context_1.contextId"),
        std::vector<core::UserWithPubKey>{
            core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            },
            core::UserWithPubKey{
                .userId = reader->getString("Login.user_2_id"),
                .pubKey = reader->getString("Login.user_2_pubKey")
            }
        },
        std::vector<core::UserWithPubKey>{core::UserWithPubKey{
            .userId = reader->getString("Login.user_1_id"),
            .pubKey = reader->getString("Login.user_1_pubKey")
        }},
        core::Buffer::from("public"), core::Buffer::from("private")
    );
    ASSERT_FALSE(groupId.empty());

    core::Buffer envelope;
    EXPECT_NO_THROW({ envelope = groupApi->encrypt(groupId, core::Buffer::from("secret payload")); });
    EXPECT_GT(envelope.size(), 0u);
    // The point of an envelope: it travels alone, with nothing alongside it saying how to open it.
    EXPECT_EQ(envelope.stdString().find("secret payload"), std::string::npos);

    disconnect();
    connectAs(GroupConnectionType::GUser2);

    group::DecryptedEnvelope opened;
    EXPECT_NO_THROW({ opened = groupApi->decrypt(envelope); });
    EXPECT_EQ(opened.data.stdString(), "secret payload");
    EXPECT_EQ(opened.groupId, groupId);
    EXPECT_EQ(opened.type, group::ENVELOPE_FROM_MEMBER);
    EXPECT_EQ(opened.authorPubKey, reader->getString("Login.user_1_pubKey"));
}

TEST_F(GroupTest, envelope_survives_a_key_rotation) {
    // Removing a member advances the group's key epoch. An envelope sealed before that must still open
    // afterwards — which is the whole reason the key id travels inside it.
    std::string groupId = groupApi->createGroup(
        reader->getString("Context_1.contextId"),
        std::vector<core::UserWithPubKey>{
            core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            },
            core::UserWithPubKey{
                .userId = reader->getString("Login.user_2_id"),
                .pubKey = reader->getString("Login.user_2_pubKey")
            }
        },
        std::vector<core::UserWithPubKey>{core::UserWithPubKey{
            .userId = reader->getString("Login.user_1_id"),
            .pubKey = reader->getString("Login.user_1_pubKey")
        }},
        core::Buffer::from("public"), core::Buffer::from("private")
    );
    ASSERT_FALSE(groupId.empty());

    core::Buffer before = groupApi->encrypt(groupId, core::Buffer::from("written before the rotation"));
    const int64_t epochBefore = groupApi->getGroup(groupId).keyVersion;

    EXPECT_NO_THROW({
        groupApi->removeGroupMembers(groupId, {reader->getString("Login.user_2_id")});
    });
    EXPECT_GT(groupApi->getGroup(groupId).keyVersion, epochBefore);

    group::DecryptedEnvelope opened;
    EXPECT_NO_THROW({ opened = groupApi->decrypt(before); });
    EXPECT_EQ(opened.data.stdString(), "written before the rotation");
}

TEST_F(GroupTest, envelope_from_a_non_member) {
    // A group user_2 is deliberately not in.
    std::string groupId = groupApi->createGroup(
        reader->getString("Context_1.contextId"),
        std::vector<core::UserWithPubKey>{core::UserWithPubKey{
            .userId = reader->getString("Login.user_1_id"),
            .pubKey = reader->getString("Login.user_1_pubKey")
        }},
        std::vector<core::UserWithPubKey>{core::UserWithPubKey{
            .userId = reader->getString("Login.user_1_id"),
            .pubKey = reader->getString("Login.user_1_pubKey")
        }},
        core::Buffer::from("public"), core::Buffer::from("private")
    );
    ASSERT_FALSE(groupId.empty());
    const std::string groupPubKey = groupApi->getGroup(groupId).groupPubKey;
    ASSERT_FALSE(groupPubKey.empty());

    disconnect();
    connectAs(GroupConnectionType::GUser2);

    // Not a member: reading the group is refused, but sealing to it is not — that asymmetry is the feature.
    EXPECT_ANY_THROW({ groupApi->getGroup(groupId); });
    core::Buffer envelope;
    EXPECT_NO_THROW({
        envelope = groupApi->encryptAnonymously(groupId, groupPubKey, core::Buffer::from("a tip from outside"));
    });
    // The sender cannot read back what they wrote; only the group can.
    EXPECT_ANY_THROW({ groupApi->decrypt(envelope); });

    disconnect();
    connectAs(GroupConnectionType::GUser1);
    group::DecryptedEnvelope opened;
    EXPECT_NO_THROW({ opened = groupApi->decrypt(envelope); });
    EXPECT_EQ(opened.data.stdString(), "a tip from outside");
    EXPECT_EQ(opened.type, group::ENVELOPE_ANONYMOUS);
    // Anonymous means anonymous — no author is reported, not even the throwaway key that sealed it.
    EXPECT_TRUE(opened.authorPubKey.empty());
}

TEST_F(GroupTest, envelope_file_roundtrip_as_documented) {
    // The sealing and opening examples from GroupApi.hpp, run against a real bridge exactly as written.
    // So the snippets below can be pasted in exactly as the header writes them.
    using namespace privmx::endpoint::group;
    auto& api = *groupApi;
    std::string groupId = api.createGroup(
        reader->getString("Context_1.contextId"),
        std::vector<core::UserWithPubKey>{
            core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            },
            core::UserWithPubKey{
                .userId = reader->getString("Login.user_2_id"),
                .pubKey = reader->getString("Login.user_2_pubKey")
            }
        },
        std::vector<core::UserWithPubKey>{core::UserWithPubKey{
            .userId = reader->getString("Login.user_1_id"),
            .pubKey = reader->getString("Login.user_1_pubKey")
        }},
        core::Buffer::from("public"), core::Buffer::from("private")
    );
    ASSERT_FALSE(groupId.empty());

    // Deliberately not a whole number of chunks, so the short final chunk is exercised.
    std::string plain;
    for (int i = 0; plain.size() < 2 * 1024 * 1024 + 12345; ++i) {
        plain.append("chunk-" + std::to_string(i) + "-payload;");
    }
    ByteSource source{plain};
    ByteSink sink;
    const std::size_t plaintextSize = plain.size();

    // --- verbatim from GroupApi.hpp, beginFileEncryption ---
    FileHandle h = api.beginFileEncryption(groupId, plaintextSize);
    while (source.hasMore()) {
        sink.write(api.encryptFileChunk(h, source.read(1 << 20)));  // may write nothing; that is normal
    }
    Envelope envelope = api.finishFileEncryption(h);  // keep this alongside the ciphertext
    // --- end verbatim ---

    EXPECT_GT(sink.data.size(), plain.size());
    EXPECT_EQ(sink.data.find("chunk-0-payload"), std::string::npos);

    // The ciphertext and the envelope travel to whoever reads it; nothing else is needed.
    CipherStorage storage{sink.data};
    disconnect();
    connectAs(GroupConnectionType::GUser2);

    // A scope of its own so `api`, `h` and `sink` name this connection's reader, letting the example below
    // stay character-for-character what the header says.
    {
        auto& api = *groupApi;
        ByteSink sink;

        // --- verbatim from GroupApi.hpp, beginFileDecryption ---
        FileHandle h = api.beginFileDecryption(envelope);
        while (storage.hasMore()) {
            sink.write(api.decryptFileChunk(h, storage.read(1 << 20)));
        }
        DecryptedFileInfo info = api.finishFileDecryption(h);  // who sent it, and was it whole
        // --- end verbatim ---

        EXPECT_EQ(sink.data, plain);
        EXPECT_EQ(info.groupId, groupId);
        EXPECT_EQ(info.type, ENVELOPE_FROM_MEMBER);
        EXPECT_EQ(info.authorPubKey, reader->getString("Login.user_1_pubKey"));
        // A straight read start to finish is exactly the case that keeps the whole-file guarantee.
        EXPECT_TRUE(info.complete);
    }
}

TEST_F(GroupTest, envelope_file_truncation_is_detected) {
    std::string groupId = groupApi->createGroup(
        reader->getString("Context_1.contextId"),
        std::vector<core::UserWithPubKey>{core::UserWithPubKey{
            .userId = reader->getString("Login.user_1_id"),
            .pubKey = reader->getString("Login.user_1_pubKey")
        }},
        std::vector<core::UserWithPubKey>{core::UserWithPubKey{
            .userId = reader->getString("Login.user_1_id"),
            .pubKey = reader->getString("Login.user_1_pubKey")
        }},
        core::Buffer::from("public"), core::Buffer::from("private")
    );
    ASSERT_FALSE(groupId.empty());

    const std::string plain(300 * 1024, 'x'); // three chunks
    int64_t writeHandle = groupApi->beginFileEncryption(groupId, (int64_t)plain.size());
    std::string cipher = groupApi->encryptFileChunk(writeHandle, core::Buffer::from(plain)).stdString();
    core::Buffer envelope = groupApi->finishFileEncryption(writeHandle);

    // Feed back everything but the final chunk. Each chunk that did arrive verifies on its own, so the only
    // thing that can notice the missing tail is the size signed into the envelope.
    int64_t readHandle = groupApi->beginFileDecryption(envelope);
    const std::size_t twoChunks = 2 * (1 + 16 + (128 * 1024 + 16) + 16);
    groupApi->decryptFileChunk(readHandle, core::Buffer::from(cipher.substr(0, twoChunks)));
    EXPECT_THROW({ groupApi->finishFileDecryption(readHandle); }, core::Exception);
    // The handle is gone even though the close threw — otherwise the file key would outlive the failure.
    EXPECT_ANY_THROW({ groupApi->finishFileDecryption(readHandle); });
}

TEST_F(GroupTest, envelope_file_range_read_as_documented) {
    // The range-reading example from GroupApi.hpp::seekInEncryptedFile, run as written.
    // So the snippets below can be pasted in exactly as the header writes them.
    using namespace privmx::endpoint::group;
    auto& api = *groupApi;
    std::string groupId = api.createGroup(
        reader->getString("Context_1.contextId"),
        std::vector<core::UserWithPubKey>{core::UserWithPubKey{
            .userId = reader->getString("Login.user_1_id"),
            .pubKey = reader->getString("Login.user_1_pubKey")
        }},
        std::vector<core::UserWithPubKey>{core::UserWithPubKey{
            .userId = reader->getString("Login.user_1_id"),
            .pubKey = reader->getString("Login.user_1_pubKey")
        }},
        core::Buffer::from("public"), core::Buffer::from("private")
    );
    ASSERT_FALSE(groupId.empty());

    std::string plain;
    for (int i = 0; plain.size() < 600 * 1024; ++i) {
        plain.append("seek-" + std::to_string(i) + "-marker;");
    }

    FileHandle writeHandle = api.beginFileEncryption(groupId, plain.size());
    std::string cipher = api.encryptFileChunk(writeHandle, core::Buffer::from(plain)).stdString();
    Envelope envelope = api.finishFileEncryption(writeHandle);

    CipherStorage storage{cipher};
    // Deliberately mid-chunk, so the promised head trim is what makes the result line up.
    const std::size_t from = 300 * 1024 + 777;
    const std::size_t length = 50 * 1024;

    // --- verbatim from GroupApi.hpp, seekInEncryptedFile ---
    FileHandle h = api.beginFileDecryption(envelope);
    CipherOffset at = api.seekInEncryptedFile(h, from);

    std::string out;
    while (out.size() < length) {
        core::Buffer block = storage.read(at, 1 << 20);  // your storage, your transport
        if (block.size() == 0) break;                    // ran off the end of the ciphertext
        at += block.size();
        out += api.decryptFileChunk(h, block).stdString();
    }
    out.resize(length);                                  // front is exact, tail may overshoot
    api.finishFileDecryption(h);
    // --- end verbatim ---

    // The documentation promises the output begins exactly at `from`, despite `from` landing mid-chunk.
    EXPECT_EQ(out, plain.substr(from, length));
    // ...and that the offset it hands back points at a chunk boundary, never into the middle of one.
    const std::size_t encryptedChunk = 1 + 16 + (128 * 1024 + 16) + 16;
    EXPECT_EQ(api.seekInEncryptedFile(api.beginFileDecryption(envelope), from) % encryptedChunk, 0);

    // ...and that a seeked handle gives up the whole-file guarantee, while a straight read keeps it.
    FileHandle seeked = api.beginFileDecryption(envelope);
    api.seekInEncryptedFile(seeked, from);
    api.decryptFileChunk(seeked, core::Buffer::from(cipher.substr(at - (at % encryptedChunk))));
    EXPECT_FALSE(api.finishFileDecryption(seeked).complete);

    FileHandle whole = api.beginFileDecryption(envelope);
    api.decryptFileChunk(whole, core::Buffer::from(cipher));
    EXPECT_TRUE(api.finishFileDecryption(whole).complete);

    // Seeking past the end is a caller error, not a silent clamp.
    FileHandle bad = api.beginFileDecryption(envelope);
    EXPECT_THROW({ api.seekInEncryptedFile(bad, (int64_t)plain.size() + 1); }, core::Exception);
    api.seekInEncryptedFile(bad, plain.size());
    api.finishFileDecryption(bad);
}

TEST_F(GroupTest, envelope_repeated_decrypt_and_two_keys_in_one_session) {
    // Opening many envelopes reuses one unwrapped key, and a rotation puts a second key in play alongside it.
    // The risk this guards is not speed but the memo handing back the wrong key once two are cached at once.
    std::string groupId = groupApi->createGroup(
        reader->getString("Context_1.contextId"),
        std::vector<core::UserWithPubKey>{
            core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            },
            core::UserWithPubKey{
                .userId = reader->getString("Login.user_2_id"),
                .pubKey = reader->getString("Login.user_2_pubKey")
            }
        },
        std::vector<core::UserWithPubKey>{core::UserWithPubKey{
            .userId = reader->getString("Login.user_1_id"),
            .pubKey = reader->getString("Login.user_1_pubKey")
        }},
        core::Buffer::from("public"), core::Buffer::from("private")
    );
    ASSERT_FALSE(groupId.empty());

    std::vector<core::Buffer> envelopes;
    for (int i = 0; i < 20; ++i) {
        envelopes.push_back(groupApi->encrypt(groupId, core::Buffer::from("message " + std::to_string(i))));
    }
    // Every one of these but the first should be served from the unwrapped-key memo. Correctness is what is
    // assertable here; that they cost no round trips is structural, not something the test can observe.
    for (int i = 0; i < 20; ++i) {
        group::DecryptedEnvelope opened;
        EXPECT_NO_THROW({ opened = groupApi->decrypt(envelopes[i]); });
        EXPECT_EQ(opened.data.stdString(), "message " + std::to_string(i));
        EXPECT_EQ(opened.groupId, groupId);
    }

    // A removal mints a new metadata key, so from here two distinct keyIds are live in the same session.
    ASSERT_NO_THROW({ groupApi->removeGroupMembers(groupId, {reader->getString("Login.user_2_id")}); });
    core::Buffer afterRotation = groupApi->encrypt(groupId, core::Buffer::from("after the rotation"));

    // Interleaved on purpose: an envelope under the new key, then one under the old, then the new one again.
    EXPECT_EQ(groupApi->decrypt(afterRotation).data.stdString(), "after the rotation");
    EXPECT_EQ(groupApi->decrypt(envelopes[7]).data.stdString(), "message 7");
    EXPECT_EQ(groupApi->decrypt(afterRotation).data.stdString(), "after the rotation");
    EXPECT_EQ(groupApi->decrypt(envelopes[19]).data.stdString(), "message 19");
}
