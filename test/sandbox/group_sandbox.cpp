// group_sandbox - performance and usage scenarios for tree-backed (Trellis) groups against a live Bridge.
//
// A gtest binary on purpose: it reuses the e2e fixtures (dataset ini, logins, connect) and gtest's filter is the
// scenario selector. Sizes and output go through extra flags read from argv. See README.md next to this file.
//
// Synthetic users are registered through the management API so groups can be far larger than the dataset's three
// logins; only the few a scenario needs are ever connected - the rest are offline members, as in real life.

#include <chrono>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <map>
#include <sstream>
#include <thread>
#include "BaseGroupTest.hpp"
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/BackendRequester.hpp>
#include <privmx/endpoint/inbox/InboxApi.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>

using namespace privmx::endpoint;
using Fields = std::vector<std::pair<std::string, std::string>>;
using Roster = std::vector<core::UserWithPubKey>;

namespace {

std::string flag(const std::string& name, const std::string& fallback) {
    const auto args = testing::internal::GetArgvs();
    for (size_t i = 0; i + 1 < args.size(); ++i) {
        if (args[i] == name) return args[i + 1];
    }
    return fallback;
}

std::vector<int> intsFlag(const std::string& name, const std::string& fallback) {
    std::vector<int> out;
    std::stringstream in(flag(name, fallback));
    for (std::string item; std::getline(in, item, ',');) out.push_back(std::stoi(item));
    return out;
}

template <typename T> std::string num(T value) {
    std::ostringstream out;
    out << std::fixed << std::setprecision(1) << value;
    return out.str();
}

std::string q(const std::string& text) {
    std::string out = "\"";
    for (char c : text) {
        if (c == '"' || c == '\\') out += '\\';
        out += (c == '\n' || c == '\r') ? ' ' : c;
    }
    return out + "\"";
}

template <typename F> double ms(F&& body) {
    const auto start = std::chrono::steady_clock::now();
    body();
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
}

// One table row on stdout, the same row as a JSON line in --out.
void report(const std::string& scenario, const Fields& fields) {
    std::ostringstream json;
    json << "{\"scenario\":" << q(scenario);
    std::cout << std::left << std::setw(4) << scenario;
    for (const auto& [key, value] : fields) {
        std::cout << " " << key << "=" << value;
        json << "," << q(key) << ":" << value;
    }
    std::cout << std::endl;
    std::ofstream(flag("--out", "group_sandbox.jsonl"), std::ios::app) << json.str() << "}\n";
}

std::string describe(const std::exception& e) {
    if (auto* p = dynamic_cast<const core::Exception*>(&e)) return p->getFull();
    if (auto* p = dynamic_cast<const privmx::utils::PrivmxException*>(&e)) return std::string(p->what()) + " " + p->getData();
    return e.what();
}

} // namespace

class GroupSandbox : public privmx::test::BaseGroupIdentityTest {
protected:
    void customSetUp() override { openReader(); }
    void customTearDown() override {
        reader.reset();
        core::EventQueueImpl::getInstance()->clear();
    }

    struct Identity {
        std::string userId, privKey, pubKey;
        core::UserWithPubKey member() const { return {.userId = userId, .pubKey = pubKey}; }
    };

    struct Session {
        std::shared_ptr<core::Connection> connection;
        std::shared_ptr<group::GroupApi> groups;
        ~Session() {
            try { if (connection) connection->disconnect(); } catch (...) {}
        }
    };

    // Shared across scenarios of one run: offline members are cheap to reuse, expensive to register.
    static inline std::vector<Identity> pool;
    static inline int registered = 0;
    // Tells this run's users apart from the last run's on a Bridge that was not reset.
    static inline const std::string runTag = std::to_string(std::chrono::system_clock::now().time_since_epoch().count() % 1000000007);

    Identity registerUser() {
        const auto key = privmx::crypto::PrivateKey::generateRandom();
        Identity id{"sbx_" + runTag + "_" + std::to_string(registered++), key.toWIF(), key.getPublicKey().toBase58DER()};
        const std::string response = core::BackendRequester::backendRequest(
            getPlatformUrl(), reader->getString("Api.apiKeyId"), reader->getString("Api.apiKeySecret"), 0,
            "context/addUserToContext",
            "{\"contextId\":\"" + contextId() + "\",\"userId\":\"" + id.userId + "\",\"userPubKey\":\"" + id.pubKey + "\"}"
        );
        if (response.find("\"error\"") != std::string::npos) throw std::runtime_error("addUserToContext: " + response);
        return id;
    }

    const Identity& pooled(size_t i) {
        while (pool.size() <= i) pool.push_back(registerUser());
        return pool[i];
    }

    // user_1 (creator, manager), user_2, user_3, then pooled synthetic users: roster position == seat.
    Roster roster(int n) {
        Roster out{user(1), user(2), user(3)};
        for (size_t i = 0; (int)out.size() < n; ++i) out.push_back(pooled(i).member());
        out.resize(n);
        return out;
    }

    std::unique_ptr<Session> open(const std::string& privKey) {
        auto session = std::make_unique<Session>();
        session->connection = connectWith(privKey);
        session->groups = std::make_shared<group::GroupApi>(group::GroupApi::create(*session->connection));
        return session;
    }

    std::string create(group::GroupApi& groups, const Roster& users, const Roster& managers = {}) {
        return groups.createGroup(
            contextId(), users, managers.empty() ? Roster{user(1)} : managers, core::Buffer::from("sbx_public"),
            core::Buffer::from("sbx_private")
        );
    }

    static void addAll(group::GroupApi& groups, const std::string& groupId, Roster::const_iterator from, Roster::const_iterator to) {
        while (from != to) {
            std::vector<group::GroupMemberToAdd> batch;
            for (; from != to && batch.size() < 128; ++from) batch.push_back({.user = *from, .role = "user"});
            groups.addGroupMembers(groupId, batch);
        }
    }

    std::string createBatched(group::GroupApi& groups, const Roster& users) {
        const auto split = users.begin() + std::min<size_t>(128, users.size());
        const std::string groupId = create(groups, Roster(users.begin(), split));
        addAll(groups, groupId, split, users.end());
        return groupId;
    }

    // Direct creation when the Bridge takes it, the batched path otherwise.
    std::string makeGroup(group::GroupApi& groups, int n) {
        const Roster users = roster(n);
        try {
            return create(groups, users);
        } catch (const std::exception&) {
            return createBatched(groups, users);
        }
    }

    // Counts/bytes of this group's documents in the sandbox Bridge's Mongo db, via mongosh in the Mongo container.
    std::map<std::string, long long> mongo(const std::string& groupId) {
        const std::string js =
            "const g=\"" + groupId + "\";const o=[];"
            "for(const c of [\"groupTreeNode\",\"groupTreeEdge\",\"groupTreeCommit\",\"groupHistoryEntry\",\"groupArchiveRung\"]){"
            "const r=db[c].aggregate([{$match:{groupId:g}},{$group:{_id:null,n:{$sum:1},b:{$sum:{$bsonSize:\"$$ROOT\"}}}}]).toArray()[0]||{n:0,b:0};"
            "o.push(c+\"_n=\"+r.n,c+\"_b=\"+r.b)}"
            "const l=db.groupTreeCommit.find({groupId:g}).sort({seq:-1}).limit(1).toArray()[0];"
            "o.push(\"lastCommit_b=\"+(l?bsonsize(l):0));"
            "o.push(\"selfUpdates=\"+db.groupTreeCommit.countDocuments({groupId:g,\"statement.op\":\"selfUpdate\"}));"
            "o.push(\"filledNodes=\"+db.groupTreeNode.countDocuments({groupId:g,publicKey:{$type:\"string\"}}));"
            "print(o.join(\" \"))";
        const std::string cmd = "docker exec " + flag("--mongo-container", "privmx_test_mongo_c1") + " mongosh --quiet " +
            flag("--mongo-db", "privmx_e2e_db_900") + " --eval '" + js + "' 2>&1";
        std::string output;
        if (FILE* pipe = popen(cmd.c_str(), "r")) {
            char buffer[4096];
            while (fgets(buffer, sizeof(buffer), pipe)) output += buffer;
            pclose(pipe);
        }
        std::map<std::string, long long> out;
        std::stringstream in(output);
        for (std::string token; in >> token;) {
            const auto eq = token.find('=');
            if (eq != std::string::npos) out[token.substr(0, eq)] = std::atoll(token.c_str() + eq + 1);
        }
        return out;
    }
    static long long treeBytes(std::map<std::string, long long>& m) { return m["groupTreeNode_b"] + m["groupTreeEdge_b"]; }

    void addMongo(Fields& f, const std::string& groupId) {
        auto m = mongo(groupId);
        for (const char* c : {"groupTreeNode", "groupTreeEdge", "groupTreeCommit", "groupHistoryEntry", "groupArchiveRung"}) {
            f.push_back({std::string(c).substr(5) + "_n", num(m[std::string(c) + "_n"])});
            f.push_back({std::string(c).substr(5) + "_b", num(m[std::string(c) + "_b"])});
        }
    }

    // Runs one row; whatever throws becomes the row's error instead of ending the scenario.
    template <typename Body> void row(const std::string& scenario, Fields f, Body body) {
        try {
            body(f);
        } catch (const std::exception& e) {
            f.push_back({"error", q(describe(e))});
            ADD_FAILURE() << scenario << ": " << describe(e);
        }
        report(scenario, f);
    }

    // A correctness check: recorded in the row and failing the gtest when false.
    static void check(Fields& f, const std::string& name, bool ok) {
        f.push_back({name, ok ? "true" : "false"});
        EXPECT_TRUE(ok) << name;
    }

    template <typename F> static bool succeeds(F&& probe) {
        try {
            return probe();
        } catch (const std::exception&) {
            return false;
        }
    }

    static core::ContainerPolicy readableByEverybody() {
        core::ContainerPolicy policy;
        policy.get = "all";
        policy.item = core::ItemPolicy{.get = "all", .listAll = "all"};
        return policy;
    }

    static std::vector<core::GroupGrantWithKey> grantTo(const group::Group& g) {
        return {{.groupId = g.groupId, .role = "user", .groupPubKey = g.groupPubKey, .groupEpoch = g.keyVersion}};
    }

    std::vector<int> sizes() { return intsFlag("--sizes", "16,64,256,1024,4096"); }
    // Repeats per size for P1-P3; medians are taken from the jsonl afterwards.
    static int reps() { return std::stoi(flag("--reps", "1")); }
};

// P1: createGroup latency and server-side footprint; direct creation and create(128)+add batches.
TEST_F(GroupSandbox, P1_create) {
    auto s = open(privKeyOf(1));
    for (int n : sizes()) {
        const Roster users = roster(n);
        for (int rep = 0; rep < reps(); ++rep)
        for (bool batched : {false, true}) {
            row("P1", {{"n", num(n)}, {"mode", q(batched ? "create+add128" : "create")}}, [&](Fields& f) {
                std::string groupId;
                f.push_back({"ms", num(ms([&] { groupId = batched ? createBatched(*s->groups, users) : create(*s->groups, users); }))});
                addMongo(f, groupId);
            });
        }
    }
}

// P2: one add and one remove on a group of n, with what each commit leaves in Mongo.
TEST_F(GroupSandbox, P2_add_remove) {
    auto s = open(privKeyOf(1));
    for (int n : sizes())
    for (int rep = 0; rep < reps(); ++rep) {
        row("P2", {{"n", num(n)}}, [&](Fields& f) {
            const std::string groupId = makeGroup(*s->groups, n);
            const Identity extra = registerUser();
            auto before = mongo(groupId);
            f.push_back({"add_ms", num(ms([&] { s->groups->addGroupMembers(groupId, {{.user = extra.member(), .role = "user"}}); }))});
            auto added = mongo(groupId);
            f.push_back({"add_commit_b", num(added["lastCommit_b"])});
            f.push_back({"add_tree_delta_b", num(treeBytes(added) - treeBytes(before))});
            f.push_back({"remove_ms", num(ms([&] { s->groups->removeGroupMembers(groupId, {extra.userId}); }))});
            auto removed = mongo(groupId);
            f.push_back({"remove_commit_b", num(removed["lastCommit_b"])});
            f.push_back({"remove_tree_delta_b", num(treeBytes(removed) - treeBytes(added))});
            f.push_back({"remove_rungs_b", num(removed["groupArchiveRung_b"] - added["groupArchiveRung_b"])});
            f.push_back({"remove_history_b", num(removed["groupHistoryEntry_b"] - added["groupHistoryEntry_b"])});
        });
    }
}

// P3: a member on a brand-new connection opens the group and decrypts an envelope.
TEST_F(GroupSandbox, P3_cold_join) {
    auto s = open(privKeyOf(1));
    for (int n : sizes())
    for (int rep = 0; rep < reps(); ++rep) {
        row("P3", {{"n", num(n)}}, [&](Fields& f) {
            const std::string groupId = makeGroup(*s->groups, n);
            const group::Envelope envelope = s->groups->encrypt(groupId, core::Buffer::from("cold"));
            std::unique_ptr<Session> member;
            std::string plain;
            const double connectMs = ms([&] { member = open(privKeyOf(2)); });
            const double decryptMs = ms([&] { plain = member->groups->decrypt(envelope).data.stdString(); });
            f.push_back({"connect_ms", num(connectMs)});
            f.push_back({"first_decrypt_ms", num(decryptMs)});
            f.push_back({"second_decrypt_ms", num(ms([&] { member->groups->decrypt(envelope); }))});
            check(f, "plaintext_ok", plain == "cold");
        });
    }
}

// P4: k removals (k epochs), then a fresh session of an old member opens an epoch-1 envelope via the ladder.
TEST_F(GroupSandbox, P4_ladder) {
    const int n = std::stoi(flag("--ladder-n", "64"));
    auto s = open(privKeyOf(1));
    for (int k : intsFlag("--ks", "1,8,32")) {
        row("P4", {{"n", num(n)}, {"k", num(k)}}, [&](Fields& f) {
            if (n < k + 3) throw std::runtime_error("--ladder-n must be at least k+3");
            const Roster users = roster(n);
            const std::string groupId = makeGroup(*s->groups, n);
            const group::Envelope old = s->groups->encrypt(groupId, core::Buffer::from("epoch1"));
            f.push_back({"removals_ms", num(ms([&] {
                for (int i = 0; i < k; ++i) s->groups->removeGroupMembers(groupId, {users[3 + i].userId});
            }))});
            const group::Envelope current = s->groups->encrypt(groupId, core::Buffer::from("now"));
            auto member = open(privKeyOf(2));
            std::string oldPlain, currentPlain;
            f.push_back({"current_decrypt_ms", num(ms([&] { currentPlain = member->groups->decrypt(current).data.stdString(); }))});
            f.push_back({"epoch1_decrypt_ms", num(ms([&] { oldPlain = member->groups->decrypt(old).data.stdString(); }))});
            f.push_back({"epoch", num(member->groups->getGroup(groupId).keyVersion)});
            check(f, "plaintext_ok", oldPlain == "epoch1" && currentPlain == "now");
            f.push_back({"rungs_n", num(mongo(groupId)["groupArchiveRung_n"])});
        });
    }
}

// P5: removals spread over buckets leave blank nodes; the next commit pays for them until members self-update.
TEST_F(GroupSandbox, P5_blanks_self_update) {
    const int n = std::stoi(flag("--blank-n", "256"));
    const int healers = std::stoi(flag("--heal-clients", "16"));
    auto s = open(privKeyOf(1));
    row("P5", {{"n", num(n)}}, [&](Fields& f) {
        const Roster users = roster(n);
        const std::string groupId = makeGroup(*s->groups, n);
        const int buckets = n / 16;
        std::vector<std::string> leavers;
        for (int b = 0; b < buckets; ++b) leavers.push_back(users[16 * b + 7].userId);
        f.push_back({"removed", num(leavers.size())});
        f.push_back({"remove_ms", num(ms([&] {
            for (size_t i = 0; i < leavers.size(); i += 128) {
                s->groups->removeGroupMembers(groupId, std::vector<std::string>(leavers.begin() + i, leavers.begin() + std::min(leavers.size(), i + 128)));
            }
        }))});
        auto addOne = [&](const std::string& tag) {
            const Identity extra = registerUser();
            auto before = mongo(groupId);
            f.push_back({tag + "_add_ms", num(ms([&] { s->groups->addGroupMembers(groupId, {{.user = extra.member(), .role = "user"}}); }))});
            auto after = mongo(groupId);
            f.push_back({tag + "_add_commit_b", num(after["lastCommit_b"])});
            f.push_back({tag + "_add_tree_delta_b", num(treeBytes(after) - treeBytes(before))});
        };
        addOne("blank");

        // Connect one surviving synthetic member per bucket; climbing past a blank node schedules a self-update
        // 0-30 s later in the background. Their seats: 16b+8, never user_1..3 (seats 0..2).
        const group::Envelope envelope = s->groups->encrypt(groupId, core::Buffer::from("heal"));
        std::vector<std::unique_ptr<Session>> online;
        for (int b = 0; b < std::min(buckets, healers); ++b) {
            online.push_back(open(pooled(16 * b + 8 - 3).privKey)); // roster(): pooled(i) sits at seat i+3
            online.back()->groups->decrypt(envelope);
        }
        // A node without a key (never set since creation, or blanked by a removal) is resolved through its children,
        // which is what makes a commit above it cost more; filled_nodes counts the keyed records that hold a key.
        auto m = mongo(groupId);
        const long long baseline = m["selfUpdates"];
        f.push_back({"filled_nodes", num(m["filledNodes"])});
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(35);
        const double waitMs = ms([&] {
            while (m["selfUpdates"] - baseline < (long long)online.size() && std::chrono::steady_clock::now() < deadline) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                m = mongo(groupId);
            }
        });
        f.push_back({"online", num(online.size())});
        f.push_back({"self_updates", num(m["selfUpdates"] - baseline)});
        f.push_back({"filled_nodes_after", num(m["filledNodes"])});
        f.push_back({"wait_ms", num(waitMs)});
        addOne("healed");
        auto fresh = open(privKeyOf(2));
        check(f, "tree_readable", fresh->groups->getGroup(groupId).statusCode == 0);
    });
}

// U1: thread granted to the group; a removed member loses messages written after the removal.
TEST_F(GroupSandbox, U1_thread_removal) {
    row("U1", {}, [&](Fields& f) {
        auto owner = open(privKeyOf(1));
        auto ownerThreads = thread::ThreadApi::create(*owner->connection, *owner->groups);
        const std::string groupId = create(*owner->groups, {user(1), user(2), user(3)});
        const std::string threadId = ownerThreads.createThread(
            contextId(), {user(1)}, {user(1)}, core::Buffer::from("pub"), core::Buffer::from("priv"),
            readableByEverybody(), grantTo(owner->groups->getGroup(groupId))
        );
        auto post = [&](const std::string& text) {
            auto poster = open(privKeyOf(2));
            return thread::ThreadApi::create(*poster->connection, *poster->groups)
                .sendMessage(threadId, core::Buffer::from("p"), core::Buffer::from("p"), core::Buffer::from(text));
        };
        auto reads = [&](int index, const std::string& messageId, const std::string& text) {
            return succeeds([&] {
                auto reader = open(privKeyOf(index));
                auto m = thread::ThreadApi::create(*reader->connection, *reader->groups).getMessage(messageId);
                return m.statusCode == 0 && m.data.stdString() == text;
            });
        };
        const std::string before = post("before");
        f.push_back({"remove_ms", num(ms([&] { owner->groups->removeGroupMembers(groupId, {userId(3)}); }))});
        f.push_back({"rekey_ms", num(ms([&] {
            const thread::Thread t = ownerThreads.getThread(threadId);
            ownerThreads.updateThread(threadId, {user(1)}, {user(1)}, t.publicMeta, t.privateMeta, t.version, false, true,
                                      readableByEverybody(), grantTo(owner->groups->getGroup(groupId)));
        }))});
        const std::string after = post("after");
        check(f, "member_reads_old", reads(2, before, "before"));
        check(f, "member_reads_new", reads(2, after, "after"));
        check(f, "removed_cannot_read_new", !reads(3, after, "after"));
        f.push_back({"removed_reads_old", reads(3, before, "before") ? "true" : "false"}); // observed, not asserted
    });
}

// U2: a file stored through a group grant is readable by someone who joins the group later.
TEST_F(GroupSandbox, U2_store_late_joiner) {
    row("U2", {}, [&](Fields& f) {
        auto owner = open(privKeyOf(1));
        auto stores = store::StoreApi::create(*owner->connection, *owner->groups);
        const std::string groupId = create(*owner->groups, {user(1), user(2)});
        const std::string storeId = stores.createStore(
            contextId(), {user(1)}, {user(1)}, core::Buffer::from("pub"), core::Buffer::from("priv"),
            readableByEverybody(), grantTo(owner->groups->getGroup(groupId))
        );
        const std::string content = "history from before the join";
        std::string fileId;
        {
            auto member = open(privKeyOf(2));
            auto memberStores = store::StoreApi::create(*member->connection, *member->groups);
            const int64_t h = memberStores.createFile(storeId, core::Buffer::from("p"), core::Buffer::from("p"), content.size());
            memberStores.writeToFile(h, core::Buffer::from(content));
            fileId = memberStores.closeFile(h);
        }
        const Identity late = registerUser();
        f.push_back({"add_ms", num(ms([&] { owner->groups->addGroupMembers(groupId, {{.user = late.member(), .role = "user"}}); }))});
        std::string read;
        f.push_back({"first_read_ms", num(ms([&] {
            auto joiner = open(late.privKey);
            auto joinerStores = store::StoreApi::create(*joiner->connection, *joiner->groups);
            const int64_t h = joinerStores.openFile(fileId);
            read = joinerStores.readFromFile(h, content.size()).stdString();
            joinerStores.closeFile(h);
        }))});
        check(f, "late_joiner_reads_history", read == content);
    });
}

// U3: two managers add members to the same group at the same time.
TEST_F(GroupSandbox, U3_concurrent_managers) {
    const int n = std::stoi(flag("--concurrent-n", "64"));
    row("U3", {{"n", num(n)}}, [&](Fields& f) {
        auto first = open(privKeyOf(1));
        auto second = open(privKeyOf(2));
        const std::string groupId = create(*first->groups, roster(n), {user(1), user(2)});
        const Identity a = registerUser(), b = registerUser();
        std::string outcome[2];
        double took[2];
        auto add = [&](int slot, group::GroupApi& groups, const Identity& who) {
            try {
                took[slot] = ms([&] { groups.addGroupMembers(groupId, {{.user = who.member(), .role = "user"}}); });
                outcome[slot] = "ok";
            } catch (const std::exception& e) {
                outcome[slot] = describe(e);
            }
        };
        std::thread t1(add, 0, std::ref(*first->groups), std::cref(a));
        std::thread t2(add, 1, std::ref(*second->groups), std::cref(b));
        t1.join();
        t2.join();
        f.push_back({"a", q(outcome[0])});
        f.push_back({"b", q(outcome[1])});
        if (outcome[0] == "ok") f.push_back({"a_ms", num(took[0])});
        if (outcome[1] == "ok") f.push_back({"b_ms", num(took[1])});
        check(f, "at_least_one_ok", outcome[0] == "ok" || outcome[1] == "ok");
        auto fresh = open(privKeyOf(3));
        const group::Group g = fresh->groups->getGroup(groupId);
        auto has = [&](const Identity& id) { return std::find(g.users.begin(), g.users.end(), id.userId) != g.users.end(); };
        check(f, "fresh_read_ok", g.statusCode == 0);
        check(f, "roster_matches", has(a) == (outcome[0] == "ok") && has(b) == (outcome[1] == "ok"));
        check(f, "added_can_decrypt", succeeds([&] {
            auto joiner = open(outcome[0] == "ok" ? a.privKey : b.privKey);
            return joiner->groups->getGroup(groupId).statusCode == 0;
        }));
    });
}

// U4: an anonymous inbox submission, decrypted by a member through the group grant.
TEST_F(GroupSandbox, U4_inbox_anonymous) {
    row("U4", {}, [&](Fields& f) {
        auto owner = open(privKeyOf(1));
        auto threads = thread::ThreadApi::create(*owner->connection, *owner->groups);
        auto stores = store::StoreApi::create(*owner->connection, *owner->groups);
        auto inboxes = inbox::InboxApi::create(*owner->connection, threads, stores, *owner->groups);
        const std::string groupId = create(*owner->groups, {user(1), user(2)});
        const group::Group g = owner->groups->getGroup(groupId);
        const std::string inboxId = inboxes.createInbox(
            contextId(), {user(1)}, {user(1)}, core::Buffer::from("pub"), core::Buffer::from("priv"), std::nullopt,
            core::ContainerPolicyWithoutItem(), {{.groupId = g.groupId, .role = "user", .groupPubKey = g.groupPubKey}}
        );
        {
            auto anon = core::Connection::connectPublic(reader->getString("Login.solutionId"), getPlatformUrl());
            auto anonThreads = thread::ThreadApi::create(anon);
            auto anonStores = store::StoreApi::create(anon);
            auto anonInboxes = inbox::InboxApi::create(anon, anonThreads, anonStores);
            anonInboxes.sendEntry(anonInboxes.prepareEntry(inboxId, core::Buffer::from("anonymous tip")));
            anon.disconnect();
        }
        auto member = open(privKeyOf(2));
        auto mThreads = thread::ThreadApi::create(*member->connection, *member->groups);
        auto mStores = store::StoreApi::create(*member->connection, *member->groups);
        auto mInboxes = inbox::InboxApi::create(*member->connection, mThreads, mStores, *member->groups);
        std::string data;
        f.push_back({"read_ms", num(ms([&] {
            auto list = mInboxes.listEntries(inboxId, core::PagingQuery{.skip = 0, .limit = 10, .sortOrder = "desc"});
            if (!list.readItems.empty()) data = list.readItems[0].data.stdString();
        }))});
        check(f, "member_decrypts_entry", data == "anonymous tip");
    });
}
