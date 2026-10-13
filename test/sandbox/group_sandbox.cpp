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
#include <atomic>
#include <map>
#include <mutex>
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

    // Shared across scenarios of one run: offline members are cheap to reuse, expensive to register. With
    // --pool-file the pool also survives the process (same Bridge db only): loaded first, extended in parallel.
    static inline std::vector<Identity> pool;
    static inline bool poolLoaded = false;
    static inline std::atomic<int> extras{0};
    // Tells this run's users apart from the last run's on a Bridge that was not reset.
    static inline const std::string runTag = std::to_string(std::chrono::system_clock::now().time_since_epoch().count() % 1000000007);

    Identity registerAs(const std::string& userId) {
        const auto key = privmx::crypto::PrivateKey::generateRandom();
        Identity id{userId, key.toWIF(), key.getPublicKey().toBase58DER()};
        const std::string response = core::BackendRequester::backendRequest(
            getPlatformUrl(), reader->getString("Api.apiKeyId"), reader->getString("Api.apiKeySecret"), 0,
            "context/addUserToContext",
            "{\"contextId\":\"" + contextId() + "\",\"userId\":\"" + id.userId + "\",\"userPubKey\":\"" + id.pubKey + "\"}"
        );
        if (response.find("\"error\"") != std::string::npos) throw std::runtime_error("addUserToContext: " + response);
        return id;
    }

    // An extra user outside the pool (newcomers for add, non-members).
    Identity registerUser() { return registerAs("sbx_" + runTag + "_x" + std::to_string(extras++)); }

    void ensurePool(size_t count) {
        const std::string file = flag("--pool-file", "");
        if (!poolLoaded) {
            poolLoaded = true;
            std::ifstream in(file);
            for (Identity id; !file.empty() && in >> id.userId >> id.privKey >> id.pubKey;) pool.push_back(id);
        }
        if (pool.size() >= count) return;
        const size_t start = pool.size();
        pool.resize(count);
        std::atomic<size_t> next{start};
        std::string failure;
        std::mutex failureMutex;
        const int threads = std::stoi(flag("--reg-threads", "16"));
        const double took = ms([&] {
            std::vector<std::thread> workers;
            for (int t = 0; t < threads; ++t) workers.emplace_back([&] {
                for (size_t i; (i = next++) < count;) {
                    for (int attempt = 0;; ++attempt) {
                        try {
                            pool[i] = registerAs("sbx_" + runTag + "_" + std::to_string(i));
                            break;
                        } catch (const std::exception& e) {
                            if (attempt < 3) continue;
                            std::lock_guard<std::mutex> lock(failureMutex);
                            failure = e.what();
                            return;
                        }
                    }
                }
            });
            for (auto& w : workers) w.join();
        });
        if (!failure.empty()) {
            pool.resize(start);
            throw std::runtime_error("registration: " + failure);
        }
        if (!file.empty()) {
            std::ofstream out(file, std::ios::app);
            for (size_t i = start; i < count; ++i) out << pool[i].userId << " " << pool[i].privKey << " " << pool[i].pubKey << "\n";
        }
        report("REG", {{"registered", num(count - start)}, {"pool", num(count)}, {"threads", num(threads)}, {"ms", num(took)}});
    }

    const Identity& pooled(size_t i) {
        ensurePool(i + 1);
        return pool[i];
    }

    // user_1 (creator, manager), user_2, user_3, then pooled synthetic users: roster position == seat.
    Roster roster(int n) {
        if (n > 3) ensurePool(n - 3);
        Roster out{user(1), user(2), user(3)};
        for (size_t i = 0; (int)out.size() < n; ++i) out.push_back(pool[i].member());
        out.resize(n);
        return out;
    }

    // Bridge-log markers: a management call (context/getContext, never made by the client library) whose k-th
    // occurrence in the RequestLogger output is the k-th line of --markers. perf_parse.py splits the log on them.
    void mark(const std::string& name) {
        core::BackendRequester::backendRequest(
            getPlatformUrl(), reader->getString("Api.apiKeyId"), reader->getString("Api.apiKeySecret"), 0,
            "context/getContext", "{\"contextId\":\"" + contextId() + "\"}"
        );
        const long long now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        std::ofstream(flag("--markers", "markers.txt"), std::ios::app) << name << " " << now << "\n";
    }

    // A measured phase: wall ms into `<key>_ms`, its Bridge requests between markers `<tag>|<key>>` and `<tag>|<key><`.
    template <typename Body> double timed(Fields& f, const std::string& tag, const std::string& key, Body&& body) {
        mark(tag + "|" + key + ">");
        double took = 0;
        try {
            took = ms(body);
        } catch (...) {
            mark(tag + "|" + key + "<");
            throw;
        }
        mark(tag + "|" + key + "<");
        f.push_back({key + "_ms", num(took)});
        return took;
    }

    static std::string tagOf(const std::string& scenario, int n, int rep = 0, const std::string& extra = "") {
        return scenario + ".n" + std::to_string(n) + ".r" + std::to_string(rep) + extra;
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
            "for(const c of [\"groupTreeNode\",\"groupTreeEdge\",\"groupTreeCommit\",\"groupHistoryEntry\",\"groupArchiveRung\",\"groupEpochKey\"]){"
            "const r=db[c].aggregate([{$match:{groupId:g}},{$group:{_id:null,n:{$sum:1},b:{$sum:{$bsonSize:\"$$ROOT\"}}}}]).toArray()[0]||{n:0,b:0};"
            "o.push(c+\"_n=\"+r.n,c+\"_b=\"+r.b)}"
            "const l=db.groupTreeCommit.find({groupId:g}).sort({seq:-1}).limit(1).toArray()[0];"
            "o.push(\"lastCommit_b=\"+(l?bsonsize(l):0));"
            "o.push(\"selfUpdates=\"+db.groupTreeCommit.countDocuments({groupId:g,\"statement.op\":\"selfUpdate\"}));"
            "o.push(\"filledNodes=\"+db.groupTreeNode.countDocuments({groupId:g,publicKey:{$type:\"string\"}}));"
            "const d=db.group.findOne({_id:g})||db.group.findOne({id:g});"
            "o.push(\"group_b=\"+(d?bsonsize(d):0));"
            "o.push(\"roster_b=\"+(d?bsonsize({u:d.users||[],m:d.managers||[],l:d.leafAssignment||[]}):0));"
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
        for (const char* c : {"groupTreeNode", "groupTreeEdge", "groupTreeCommit", "groupHistoryEntry", "groupArchiveRung", "groupEpochKey"}) {
            f.push_back({std::string(c).substr(5) + "_n", num(m[std::string(c) + "_n"])});
            f.push_back({std::string(c).substr(5) + "_b", num(m[std::string(c) + "_b"])});
        }
        for (const char* k : {"group_b", "roster_b", "lastCommit_b", "filledNodes"}) f.push_back({k, num(m[k])});
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
    // How long P5/P6 wait for background self-updates: a node's healer lands within one window of the climb that
    // scheduled it, a stand-in within two (window = 8 ms per seat, 1-120 s; `scheduleSelfUpdateIfNeeded`).
    static int healWait() { return std::stoi(flag("--heal-wait", "245")); }

    // The group's counters once `want` self-updates landed since `baseline`, or `healWait()` ran out.
    std::map<std::string, long long> waitSelfUpdates(const std::string& groupId, long long baseline, long long want) {
        auto m = mongo(groupId);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(healWait());
        while (m["selfUpdates"] - baseline < want && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            m = mongo(groupId);
        }
        return m;
    }

    // The error `groups` gets opening `envelope`; empty when it decrypts.
    static std::string decryptError(group::GroupApi& groups, const group::Envelope& envelope) {
        try {
            groups.decrypt(envelope);
            return "";
        } catch (const std::exception& e) {
            return describe(e);
        }
    }
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
            if (n <= 16) return;
            // The last seat: a bucket far from the creator's, connect excluded as above.
            auto far = open(pooled(n - 1 - 3).privKey);
            std::string farPlain;
            f.push_back({"far_first_decrypt_ms", num(ms([&] { farPlain = far->groups->decrypt(envelope).data.stdString(); }))});
            check(f, "far_plaintext_ok", farPlain == "cold");
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
        const double waitMs = ms([&] { m = waitSelfUpdates(groupId, baseline, (long long)online.size()); });
        f.push_back({"online", num(online.size())});
        f.push_back({"self_updates", num(m["selfUpdates"] - baseline)});
        f.push_back({"filled_nodes_after", num(m["filledNodes"])});
        f.push_back({"wait_ms", num(waitMs)});
        addOne("healed");
        auto fresh = open(privKeyOf(2));
        check(f, "tree_readable", fresh->groups->getGroup(groupId).statusCode == 0);
    });
}

// P6: a second manager removes the creator, right after creation and after some buckets healed. The creator set every
// keyed node at creation, so its removal blanks all of them except the remover's path and what healers re-set since.
TEST_F(GroupSandbox, P6_creator_removal) {
    const int n = std::stoi(flag("--creator-n", "1024"));
    const int healers = std::min(n / 32 - 1, std::stoi(flag("--heal-clients", "16")));
    auto creator = open(privKeyOf(1));
    auto remover = open(privKeyOf(2));
    for (bool heal : {false, true}) {
        row("P6", {{"n", num(n)}, {"mode", q(heal ? "after_healing" : "fresh")}}, [&](Fields& f) {
            const std::string groupId = create(*creator->groups, roster(n), {user(1), user(2)});
            const group::Envelope before = creator->groups->encrypt(groupId, core::Buffer::from("before"));
            check(f, "creator_reads_before", decryptError(*creator->groups, before).empty());
            std::vector<std::unique_ptr<Session>> online;
            if (heal) {
                // One member in each of buckets 1..healers (32 seats: the lowest keyed level); a node the creator set
                // off its path makes them self-update.
                const long long baseline = mongo(groupId)["selfUpdates"];
                for (int b = 1; b <= healers; ++b) {
                    online.push_back(open(pooled(32 * b + 8 - 3).privKey));
                    online.back()->groups->decrypt(before);
                }
                auto m = waitSelfUpdates(groupId, baseline, healers);
                f.push_back({"online", num(healers)});
                f.push_back({"self_updates", num(m["selfUpdates"] - baseline)});
            }
            auto m = mongo(groupId);
            f.push_back({"filled_before", num(m["filledNodes"])});
            f.push_back({"remove_ms", num(ms([&] { remover->groups->removeGroupMembers(groupId, {userId(1)}); }))});
            auto removed = mongo(groupId);
            f.push_back({"filled_after", num(removed["filledNodes"])});
            f.push_back({"remove_commit_b", num(removed["lastCommit_b"])});
            f.push_back({"remove_tree_delta_b", num(treeBytes(removed) - treeBytes(m))});
            const Identity extra = registerUser();
            f.push_back({"add_after_ms", num(ms([&] { remover->groups->addGroupMembers(groupId, {{.user = extra.member(), .role = "user"}}); }))});
            const group::Envelope after = remover->groups->encrypt(groupId, core::Buffer::from("after"));
            auto far = open(pooled(n - 1 - 3).privKey); // last bucket, never a healer
            std::string farPlain;
            f.push_back({"far_decrypt_ms", num(ms([&] { farPlain = far->groups->decrypt(after).data.stdString(); }))});
            check(f, "far_reads_after", farPlain == "after");
            check(f, "new_member_reads_after", decryptError(*open(extra.privKey)->groups, after).empty());
            // The creator's own session: a second login of the same key in this process is refused by the server.
            const std::string creatorError = decryptError(*creator->groups, after);
            check(f, "creator_cannot_read_after", !creatorError.empty());
            f.push_back({"creator_error", q(creatorError.substr(0, 160))});
        });
    }
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

// U5: someone added after k removals opens an envelope and a store file written at epoch 1 (ladder descent).
TEST_F(GroupSandbox, U5_late_joiner_ladder) {
    const int k = std::stoi(flag("--late-k", "4"));
    row("U5", {{"k", num(k)}}, [&](Fields& f) {
        auto owner = open(privKeyOf(1));
        auto stores = store::StoreApi::create(*owner->connection, *owner->groups);
        const Roster users = roster(k + 3);
        const std::string groupId = create(*owner->groups, users);
        const std::string storeId = stores.createStore(
            contextId(), {user(1)}, {user(1)}, core::Buffer::from("pub"), core::Buffer::from("priv"),
            readableByEverybody(), grantTo(owner->groups->getGroup(groupId))
        );
        const std::string content = "written at epoch 1";
        const int64_t h = stores.createFile(storeId, core::Buffer::from("p"), core::Buffer::from("p"), content.size());
        stores.writeToFile(h, core::Buffer::from(content));
        const std::string fileId = stores.closeFile(h);
        const group::Envelope old = owner->groups->encrypt(groupId, core::Buffer::from("epoch1"));
        for (int i = 0; i < k; ++i) owner->groups->removeGroupMembers(groupId, {users[3 + i].userId});
        const Identity late = registerUser();
        owner->groups->addGroupMembers(groupId, {{.user = late.member(), .role = "user"}});
        auto joiner = open(late.privKey);
        f.push_back({"epoch", num(joiner->groups->getGroup(groupId).keyVersion)});
        std::string oldPlain, read;
        f.push_back({"envelope_decrypt_ms", num(ms([&] { oldPlain = joiner->groups->decrypt(old).data.stdString(); }))});
        f.push_back({"file_read_ms", num(ms([&] {
            auto joinerStores = store::StoreApi::create(*joiner->connection, *joiner->groups);
            const int64_t r = joinerStores.openFile(fileId);
            read = joinerStores.readFromFile(r, content.size()).stdString();
            joinerStores.closeFile(r);
        }))});
        check(f, "joiner_reads_epoch1_envelope", oldPlain == "epoch1");
        check(f, "joiner_reads_epoch1_file", read == content);
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

// ---- perf-16k scenarios (S1-S9). Every measured phase is bracketed by Bridge-log markers (see mark()).

namespace {
constexpr int MAX_MEMBERS = 16384; // TypesValidator.MAX_GROUP_MEMBERS on the Bridge
std::string arr(const std::vector<double>& values) {
    std::string out = "[";
    for (size_t i = 0; i < values.size(); ++i) out += (i ? "," : "") + num(values[i]);
    return out + "]";
}
} // namespace

// S1: direct createGroup; if it is refused, create(128) + add batches instead, with the refusal recorded.
TEST_F(GroupSandbox, S1_create) {
    auto s = open(privKeyOf(1));
    for (int n : sizes()) {
        const Roster users = roster(n);
        for (int rep = 0; rep < (n >= MAX_MEMBERS ? 1 : reps()); ++rep) {
            const std::string tag = tagOf("S1", n, rep);
            row("S1", {{"n", num(n)}, {"rep", num(rep)}, {"tag", q(tag)}}, [&](Fields& f) {
                std::string groupId;
                try {
                    timed(f, tag, "create", [&] { groupId = create(*s->groups, users); });
                } catch (const std::exception& e) {
                    f.push_back({"create_error", q(describe(e))});
                    timed(f, tag, "create_batched", [&] { groupId = createBatched(*s->groups, users); });
                }
                addMongo(f, groupId);
            });
        }
    }
}

// S2: one add and one remove on a fresh dense group (n-1 members at the maximum, so the add fits).
TEST_F(GroupSandbox, S2_add_remove) {
    auto s = open(privKeyOf(1));
    for (int n : sizes())
    for (int rep = 0; rep < reps(); ++rep) {
        const std::string tag = tagOf("S2", n, rep);
        const int members = std::min(n, MAX_MEMBERS - 1);
        row("S2", {{"n", num(members)}, {"rep", num(rep)}, {"tag", q(tag)}}, [&](Fields& f) {
            const std::string groupId = create(*s->groups, roster(members));
            const Identity extra = registerUser();
            auto before = mongo(groupId);
            timed(f, tag, "add", [&] { s->groups->addGroupMembers(groupId, {{.user = extra.member(), .role = "user"}}); });
            auto added = mongo(groupId);
            f.push_back({"add_commit_b", num(added["lastCommit_b"])});
            f.push_back({"add_tree_delta_b", num(treeBytes(added) - treeBytes(before))});
            timed(f, tag, "remove", [&] { s->groups->removeGroupMembers(groupId, {extra.userId}); });
            auto removed = mongo(groupId);
            f.push_back({"remove_commit_b", num(removed["lastCommit_b"])});
            f.push_back({"remove_tree_delta_b", num(treeBytes(removed) - treeBytes(added))});
            f.push_back({"remove_rungs_b", num(removed["groupArchiveRung_b"] - added["groupArchiveRung_b"])});
            addMongo(f, groupId);
        });
    }
}

// S3: cold first read (new connection, first decrypt) for seat 1 and the last seat; then, at the largest size, a
// non-member thread manager who grants a thread to the group by id only (fetchGroupEpochs) and writes to it.
TEST_F(GroupSandbox, S3_cold_read) {
    auto s = open(privKeyOf(1));
    std::string lastGroup;
    int lastN = 0;
    for (int n : sizes()) {
        const std::string groupId = create(*s->groups, roster(n));
        const group::Envelope envelope = s->groups->encrypt(groupId, core::Buffer::from("cold"));
        lastGroup = groupId;
        lastN = n;
        for (int rep = 0; rep < reps(); ++rep) {
            const std::string tag = tagOf("S3", n, rep);
            row("S3", {{"n", num(n)}, {"rep", num(rep)}, {"tag", q(tag)}}, [&](Fields& f) {
                std::unique_ptr<Session> member, far;
                std::string plain, farPlain;
                timed(f, tag, "seat1_connect", [&] { member = open(privKeyOf(2)); });
                timed(f, tag, "seat1_first_decrypt", [&] { plain = member->groups->decrypt(envelope).data.stdString(); });
                timed(f, tag, "seat1_second_decrypt", [&] { member->groups->decrypt(envelope); });
                timed(f, tag, "far_connect", [&] { far = open(pooled(n - 1 - 3).privKey); });
                timed(f, tag, "far_first_decrypt", [&] { farPlain = far->groups->decrypt(envelope).data.stdString(); });
                check(f, "plaintext_ok", plain == "cold" && farPlain == "cold");
            });
        }
    }
    const std::string tag = tagOf("S3nm", lastN);
    // The outsider is a Thread user but not a group member; the Thread is granted to the group. Writes use the
    // Thread key; a re-key re-wraps it to the group's current epoch, which the outsider must read from the Bridge
    // when not handed the epoch key (fetchGroupEpochs: the listing, then `groupGet` for a group it has not pinned;
    // the default policy may refuse that: then the error is shown).
    row("S3nm", {{"n", num(lastN)}, {"tag", q(tag)}}, [&](Fields& f) {
        const Identity outsider = registerUser();
        auto ownerThreads = thread::ThreadApi::create(*s->connection, *s->groups);
        const group::Group g = s->groups->getGroup(lastGroup);
        const std::string threadId = ownerThreads.createThread(
            contextId(), {user(1), outsider.member()}, {user(1)}, core::Buffer::from("p"), core::Buffer::from("p"),
            readableByEverybody(), grantTo(g)
        );
        std::unique_ptr<Session> nm;
        timed(f, tag, "connect", [&] { nm = open(outsider.privKey); });
        auto threads = thread::ThreadApi::create(*nm->connection, *nm->groups);
        timed(f, tag, "first_send", [&] { threads.sendMessage(threadId, core::Buffer::from("p"), core::Buffer::from("p"), core::Buffer::from("nm")); });
        timed(f, tag, "second_send", [&] { threads.sendMessage(threadId, core::Buffer::from("p"), core::Buffer::from("p"), core::Buffer::from("nm2")); });
        const Roster threadUsers{user(1), outsider.member()};
        std::string rotateError;
        timed(f, tag, "rotate_fetching_epochs", [&] {
            try {
                threads.rotateThreadKeys(threadId, threadUsers, {user(1)}, threads.getThread(threadId).version, false, {});
            } catch (const std::exception& e) { rotateError = describe(e); }
        });
        f.push_back({"rotate_fetching_epochs_error", q(rotateError.substr(0, 200))});
        timed(f, tag, "rotate_with_known_key", [&] {
            threads.rotateThreadKeys(threadId, threadUsers, {user(1)}, threads.getThread(threadId).version, false, grantTo(g));
        });
        timed(f, tag, "third_send", [&] { threads.sendMessage(threadId, core::Buffer::from("p"), core::Buffer::from("p"), core::Buffer::from("nm3")); });
        // A member who reads only through the group sees what the outsider wrote.
        auto member = open(privKeyOf(2));
        auto memberThreads = thread::ThreadApi::create(*member->connection, *member->groups);
        std::string read;
        timed(f, tag, "member_cold_read", [&] {
            auto list = memberThreads.listMessages(threadId, core::PagingQuery{.skip = 0, .limit = 1, .sortOrder = "desc"});
            if (!list.readItems.empty()) read = list.readItems[0].data.stdString();
        });
        check(f, "member_reads_outsider_message", read == "nm3");
    });
}

// S4: a second manager removes the creator right after creation (closure = every node the creator set), then adds one.
TEST_F(GroupSandbox, S4_creator_removal) {
    auto creator = open(privKeyOf(1));
    auto remover = open(privKeyOf(2));
    for (int n : intsFlag("--s4-sizes", "4096,16384")) {
        const std::string tag = tagOf("S4", n);
        const int members = std::min(n, MAX_MEMBERS - 2); // the two adds after the removal must fit under the cap
        row("S4", {{"n", num(members)}, {"tag", q(tag)}}, [&](Fields& f) {
            std::string groupId;
            timed(f, tag, "create", [&] { groupId = create(*creator->groups, roster(members), {user(1), user(2)}); });
            auto m = mongo(groupId);
            f.push_back({"filled_before", num(m["filledNodes"])});
            timed(f, tag, "remove_creator", [&] { remover->groups->removeGroupMembers(groupId, {userId(1)}); });
            auto removed = mongo(groupId);
            f.push_back({"filled_after", num(removed["filledNodes"])});
            f.push_back({"remove_commit_b", num(removed["lastCommit_b"])});
            f.push_back({"remove_tree_delta_b", num(treeBytes(removed) - treeBytes(m))});
            const Identity extra = registerUser();
            timed(f, tag, "add_after", [&] { remover->groups->addGroupMembers(groupId, {{.user = extra.member(), .role = "user"}}); });
            auto added = mongo(groupId);
            f.push_back({"add_commit_b", num(added["lastCommit_b"])});
            f.push_back({"add_tree_delta_b", num(treeBytes(added) - treeBytes(removed))});
            timed(f, tag, "add2_after", [&] { remover->groups->addGroupMembers(groupId, {{.user = registerUser().member(), .role = "user"}}); });
            const group::Envelope after = remover->groups->encrypt(groupId, core::Buffer::from("after"));
            std::unique_ptr<Session> far;
            std::string farPlain;
            far = open(pooled(members - 1 - 3).privKey);
            timed(f, tag, "far_first_decrypt", [&] { farPlain = far->groups->decrypt(after).data.stdString(); });
            check(f, "far_reads_after", farPlain == "after");
            addMongo(f, groupId);
        });
    }
}

// S5: 128 members spread one per 128 seats removed in one call from a fresh 16384 group, then single adds.
TEST_F(GroupSandbox, S5_spread_removal) {
    const int n = std::stoi(flag("--s5-n", "16384"));
    auto s = open(privKeyOf(1));
    const std::string tag = tagOf("S5", n);
    row("S5", {{"n", num(n)}, {"tag", q(tag)}}, [&](Fields& f) {
        const Roster users = roster(n);
        std::string groupId;
        timed(f, tag, "create", [&] { groupId = create(*s->groups, users); });
        std::vector<std::string> leavers;
        const int spacing = n / 128;
        for (int b = 0; b < 128; ++b) leavers.push_back(users[spacing * b + spacing / 2].userId);
        auto m = mongo(groupId);
        timed(f, tag, "remove128", [&] { s->groups->removeGroupMembers(groupId, leavers); });
        auto removed = mongo(groupId);
        f.push_back({"filled_before", num(m["filledNodes"])});
        f.push_back({"filled_after", num(removed["filledNodes"])});
        f.push_back({"remove_commit_b", num(removed["lastCommit_b"])});
        f.push_back({"remove_tree_delta_b", num(treeBytes(removed) - treeBytes(m))});
        timed(f, tag, "add_after", [&] { s->groups->addGroupMembers(groupId, {{.user = registerUser().member(), .role = "user"}}); });
        auto added = mongo(groupId);
        f.push_back({"add_commit_b", num(added["lastCommit_b"])});
        f.push_back({"add_tree_delta_b", num(treeBytes(added) - treeBytes(removed))});
        timed(f, tag, "add2_after", [&] { s->groups->addGroupMembers(groupId, {{.user = registerUser().member(), .role = "user"}}); });
        addMongo(f, groupId);
    });
}

// S6: after a creator removal at n, K healer clients (one per n/K seats, distinct users) connect at once and read;
// each schedules a background self-update. Counts accepted ones (Mongo) until they stop arriving.
TEST_F(GroupSandbox, S6_self_update_storm) {
    const int n = std::stoi(flag("--s6-n", "4096"));
    auto creator = open(privKeyOf(1));
    auto remover = open(privKeyOf(2));
    for (int k : intsFlag("--s6-ks", "32,64")) {
        const std::string tag = tagOf("S6", n, 0, ".k" + std::to_string(k));
        row("S6", {{"n", num(n)}, {"k", num(k)}, {"tag", q(tag)}}, [&](Fields& f) {
            const std::string groupId = create(*creator->groups, roster(n), {user(1), user(2)});
            timed(f, tag, "remove_creator", [&] { remover->groups->removeGroupMembers(groupId, {userId(1)}); });
            const group::Envelope envelope = remover->groups->encrypt(groupId, core::Buffer::from("storm"));
            auto m = mongo(groupId);
            const long long baseline = m["selfUpdates"];
            f.push_back({"filled_before", num(m["filledNodes"])});
            std::vector<std::unique_ptr<Session>> healers(k);
            std::atomic<int> readOk{0};
            timed(f, tag, "healers_connect_read", [&] {
                std::vector<std::thread> starters;
                for (int b = 0; b < k; ++b) starters.emplace_back([&, b] {
                    try {
                        const int seat = b * (n / k) + n / (2 * k);
                        healers[b] = open(pool[seat - 3].privKey);
                        if (healers[b]->groups->decrypt(envelope).data.stdString() == "storm") ++readOk;
                    } catch (...) {}
                });
                for (auto& t : starters) t.join();
            });
            f.push_back({"healers_read_ok", num(readOk.load())});
            // Until all K landed, or nothing new for --storm-idle s (after the first 35 s), or --heal-wait s.
            const auto start = std::chrono::steady_clock::now();
            const auto deadline = start + std::chrono::seconds(std::stoi(flag("--heal-wait", "180")));
            const int idle = std::stoi(flag("--storm-idle", "45"));
            long long seen = 0;
            std::vector<double> arrivals;
            timed(f, tag, "storm", [&] {
                while (std::chrono::steady_clock::now() < deadline && seen < k) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    const long long now = mongo(groupId)["selfUpdates"] - baseline;
                    const auto t = std::chrono::steady_clock::now();
                    for (; seen < now; ++seen) arrivals.push_back(std::chrono::duration<double, std::milli>(t - start).count());
                    if (!arrivals.empty() && t - start > std::chrono::milliseconds((long long)arrivals.back()) + std::chrono::seconds(idle) &&
                        t - start > std::chrono::seconds(35)) break;
                    if (arrivals.empty() && t - start > std::chrono::seconds(35 + idle)) break;
                }
            });
            f.push_back({"accepted_self_updates", num(seen)});
            f.push_back({"converged_ms", num(arrivals.empty() ? 0.0 : arrivals.back())});
            f.push_back({"arrivals_ms", arr(arrivals)});
            healers.clear();
            auto healed = mongo(groupId);
            f.push_back({"filled_after", num(healed["filledNodes"])});
            timed(f, tag, "add_after", [&] { remover->groups->addGroupMembers(groupId, {{.user = registerUser().member(), .role = "user"}}); });
            auto added = mongo(groupId);
            f.push_back({"add_commit_b", num(added["lastCommit_b"])});
            f.push_back({"add_tree_delta_b", num(treeBytes(added) - treeBytes(healed))});
        });
    }
}

// S7: k removals at n (one per call), then a late joiner and an old member each open an epoch-1 envelope cold.
TEST_F(GroupSandbox, S7_deep_history) {
    const int n = std::stoi(flag("--s7-n", "1024"));
    const int k = std::stoi(flag("--s7-k", "100"));
    auto s = open(privKeyOf(1));
    const std::string tag = tagOf("S7", n, 0, ".k" + std::to_string(k));
    row("S7", {{"n", num(n)}, {"k", num(k)}, {"tag", q(tag)}}, [&](Fields& f) {
        const Roster users = roster(n);
        const std::string groupId = create(*s->groups, users);
        const group::Envelope old = s->groups->encrypt(groupId, core::Buffer::from("epoch1"));
        std::vector<double> each;
        for (int i = 0; i < k; ++i) {
            Fields scratch;
            each.push_back(timed(scratch, tag, "rm" + std::to_string(i), [&] { s->groups->removeGroupMembers(groupId, {users[3 + i].userId}); }));
        }
        f.push_back({"removal_ms", arr(each)});
        const group::Envelope current = s->groups->encrypt(groupId, core::Buffer::from("now"));
        const Identity late = registerUser();
        timed(f, tag, "late_add", [&] { s->groups->addGroupMembers(groupId, {{.user = late.member(), .role = "user"}}); });
        std::string a, b, c, d;
        {
            auto joiner = open(late.privKey);
            timed(f, tag, "joiner_epoch1_cold", [&] { a = joiner->groups->decrypt(old).data.stdString(); });
            timed(f, tag, "joiner_epoch1_warm", [&] { joiner->groups->decrypt(old); });
            timed(f, tag, "joiner_current", [&] { b = joiner->groups->decrypt(current).data.stdString(); });
            f.push_back({"epoch", num(joiner->groups->getGroup(groupId).keyVersion)});
        }
        {
            auto member = open(privKeyOf(2));
            timed(f, tag, "old_member_epoch1_cold", [&] { c = member->groups->decrypt(old).data.stdString(); });
            timed(f, tag, "old_member_current", [&] { d = member->groups->decrypt(current).data.stdString(); });
        }
        check(f, "plaintext_ok", a == "epoch1" && b == "now" && c == "epoch1" && d == "now");
        addMongo(f, groupId);
    });
}

// S8: a member's warm hot path on a thread granted to a large group: 20 sendMessage and 20 getMessage.
TEST_F(GroupSandbox, S8_thread_hot_path) {
    const int n = std::stoi(flag("--s8-n", "16384"));
    const int calls = std::stoi(flag("--s8-calls", "20"));
    auto owner = open(privKeyOf(1));
    const std::string tag = tagOf("S8", n);
    row("S8", {{"n", num(n)}, {"tag", q(tag)}}, [&](Fields& f) {
        const std::string groupId = create(*owner->groups, roster(n));
        auto ownerThreads = thread::ThreadApi::create(*owner->connection, *owner->groups);
        const std::string threadId = ownerThreads.createThread(
            contextId(), {user(1)}, {user(1)}, core::Buffer::from("pub"), core::Buffer::from("priv"),
            readableByEverybody(), grantTo(owner->groups->getGroup(groupId))
        );
        auto member = open(privKeyOf(2));
        auto threads = thread::ThreadApi::create(*member->connection, *member->groups);
        std::vector<std::string> ids;
        auto send = [&] { ids.push_back(threads.sendMessage(threadId, core::Buffer::from("p"), core::Buffer::from("p"), core::Buffer::from("hot"))); };
        timed(f, tag, "first_send", send);
        std::vector<double> sends, gets;
        timed(f, tag, "sends", [&] { for (int i = 0; i < calls; ++i) sends.push_back(ms(send)); });
        bool ok = true;
        timed(f, tag, "gets", [&] {
            for (int i = 0; i < calls; ++i) gets.push_back(ms([&] { ok = ok && threads.getMessage(ids[1 + i]).data.stdString() == "hot"; }));
        });
        f.push_back({"send_each_ms", arr(sends)});
        f.push_back({"get_each_ms", arr(gets)});
        check(f, "reads_ok", ok);
    });
}

// S9: four managers each add one member to the same group at the same time.
TEST_F(GroupSandbox, S9_concurrent_managers) {
    const int n = std::stoi(flag("--s9-n", "4096"));
    std::vector<std::unique_ptr<Session>> managers;
    const Roster users = roster(n);
    for (int i = 1; i <= 3; ++i) managers.push_back(open(privKeyOf(i)));
    managers.push_back(open(pool[0].privKey));
    for (int rep = 0; rep < reps(); ++rep) {
        const std::string tag = tagOf("S9", n, rep);
        row("S9", {{"n", num(n)}, {"rep", num(rep)}, {"tag", q(tag)}}, [&](Fields& f) {
            const std::string groupId = create(*managers[0]->groups, users, {user(1), user(2), user(3), pool[0].member()});
            for (auto& m : managers) m->groups->getGroup(groupId); // each manager starts warm, as a live client would
            std::vector<Identity> newcomers;
            for (int i = 0; i < 4; ++i) newcomers.push_back(registerUser());
            std::string outcome[4];
            double took[4] = {0, 0, 0, 0};
            timed(f, tag, "concurrent_adds", [&] {
                std::vector<std::thread> adders;
                for (int i = 0; i < 4; ++i) adders.emplace_back([&, i] {
                    try {
                        took[i] = ms([&] { managers[i]->groups->addGroupMembers(groupId, {{.user = newcomers[i].member(), .role = "user"}}); });
                        outcome[i] = "ok";
                    } catch (const std::exception& e) {
                        outcome[i] = describe(e).substr(0, 200);
                    }
                });
                for (auto& t : adders) t.join();
            });
            int okCount = 0;
            for (int i = 0; i < 4; ++i) {
                f.push_back({"m" + std::to_string(i), q(outcome[i])});
                f.push_back({"m" + std::to_string(i) + "_ms", num(took[i])});
                okCount += outcome[i] == "ok";
            }
            f.push_back({"ok", num(okCount)});
            const group::Group g = managers[1]->groups->getGroup(groupId);
            int present = 0;
            for (int i = 0; i < 4; ++i) present += std::find(g.users.begin(), g.users.end(), newcomers[i].userId) != g.users.end();
            check(f, "roster_matches", present == okCount);
        });
    }
}

// S10: one groupList page over many large groups of the caller (BSONObjectTooLarge under the old `$facet`).
TEST_F(GroupSandbox, S10_group_list) {
    const int n = std::stoi(flag("--s10-n", "16384"));
    const int groups = std::stoi(flag("--s10-groups", "40"));
    const int limit = std::stoi(flag("--s10-limit", "100"));
    auto s = open(privKeyOf(1));
    const std::string tag = tagOf("S10", n, 0, ".g" + std::to_string(groups));
    row("S10", {{"n", num(n)}, {"groups", num(groups)}, {"limit", num(limit)}, {"tag", q(tag)}}, [&](Fields& f) {
        const Roster users = roster(n);
        timed(f, tag, "create_all", [&] { for (int i = 0; i < groups; ++i) create(*s->groups, users); });
        core::PagingList<group::GroupSummary> page;
        auto cold = open(privKeyOf(1));
        timed(f, tag, "list_cold", [&] { page = cold->groups->listGroups(contextId(), {.skip = 0, .limit = limit, .sortOrder = "desc"}); });
        f.push_back({"listed", num(page.readItems.size())});
        f.push_back({"total", num(page.totalAvailable)});
        timed(f, tag, "list_warm", [&] { cold->groups->listGroups(contextId(), {.skip = 0, .limit = limit, .sortOrder = "desc"}); });
        check(f, "page_ok", (int)page.readItems.size() >= std::min(groups, limit));
    });
}

// R1 (review of perf-16k): epoch growth without blank accumulation. Each round removes a bucket-0 member (whose
// path is the remover's, so nothing is blanked) and adds a newcomer, so the tree stays dense while the epoch climbs.
// Afterwards: a session pinned at epoch 1 catches up, a cold getGroup, warm encrypt/decrypt loops, file chunking.
TEST_F(GroupSandbox, R1_epoch_isolation) {
    const int n = std::stoi(flag("--r1-n", "1024"));
    const int k = std::stoi(flag("--r1-k", "100"));
    auto s = open(privKeyOf(1));
    const std::string tag = tagOf("R1", n, 0, ".k" + std::to_string(k));
    row("R1", {{"n", num(n)}, {"k", num(k)}, {"tag", q(tag)}}, [&](Fields& f) {
        const Roster users = roster(n);
        const std::string groupId = create(*s->groups, users);
        const group::Envelope old = s->groups->encrypt(groupId, core::Buffer::from("epoch1"));
        auto pinned = open(privKeyOf(3));
        pinned->groups->decrypt(old); // pins user_3's session at epoch 1
        std::string leaver = users[3].userId;
        std::vector<double> removals, adds;
        for (int i = 0; i < k; ++i) {
            Fields scratch;
            removals.push_back(timed(scratch, tag, "rm" + std::to_string(i), [&] { s->groups->removeGroupMembers(groupId, {leaver}); }));
            const Identity next = registerUser();
            adds.push_back(timed(scratch, tag, "add" + std::to_string(i), [&] { s->groups->addGroupMembers(groupId, {{.user = next.member(), .role = "user"}}); }));
            leaver = next.userId;
        }
        f.push_back({"removal_ms", arr(removals)});
        f.push_back({"add_ms", arr(adds)});
        const group::Envelope current = s->groups->encrypt(groupId, core::Buffer::from("now"));
        std::string a, b;
        timed(f, tag, "pinned_catchup_decrypt", [&] { a = pinned->groups->decrypt(current).data.stdString(); });
        {
            auto cold = open(privKeyOf(2));
            timed(f, tag, "cold_getGroup", [&] { f.push_back({"epoch", num(cold->groups->getGroup(groupId).keyVersion)}); });
        }
        {
            auto cold = open(privKeyOf(2));
            timed(f, tag, "cold_decrypt_current", [&] { b = cold->groups->decrypt(current).data.stdString(); });
        }
        check(f, "plaintext_ok", a == "now" && b == "now");
        const int loops = 100;
        timed(f, tag, "encrypt_x100", [&] { for (int i = 0; i < loops; ++i) s->groups->encrypt(groupId, core::Buffer::from("x")); });
        timed(f, tag, "decrypt_x100", [&] { for (int i = 0; i < loops; ++i) s->groups->decrypt(current); });
        const std::string mib(1 << 20, 'z');
        const int64_t size = 32LL << 20;
        const std::string max(4 << 20, 'z'); // encryptFileChunk takes at most 4 MiB per call
        timed(f, tag, "file32_4mib", [&] {
            auto h = s->groups->beginFileEncryption(groupId, size);
            for (int i = 0; i < 8; ++i) s->groups->encryptFileChunk(h, core::Buffer::from(max));
            s->groups->finishFileEncryption(h);
        });
        timed(f, tag, "file32_1mib", [&] {
            auto h = s->groups->beginFileEncryption(groupId, size);
            for (int i = 0; i < 32; ++i) s->groups->encryptFileChunk(h, core::Buffer::from(mib));
            s->groups->finishFileEncryption(h);
        });
        addMongo(f, groupId);
    });
}

// R2 (review of perf-16k): the thread hot path for a member who belongs to exactly one group of n (S8's user_2 was
// in every group of the run), against a plain thread user of the same thread.
TEST_F(GroupSandbox, R2_thread_hot_path_single_group) {
    const int n = std::stoi(flag("--r2-n", "16384"));
    const int calls = std::stoi(flag("--s8-calls", "20"));
    auto owner = open(privKeyOf(1));
    const std::string tag = tagOf("R2", n);
    row("R2", {{"n", num(n)}, {"tag", q(tag)}}, [&](Fields& f) {
        const Identity x = registerUser(), plain = registerUser();
        Roster users = roster(n);
        users.back() = x.member();
        const std::string groupId = create(*owner->groups, users);
        auto ownerThreads = thread::ThreadApi::create(*owner->connection, *owner->groups);
        const std::string threadId = ownerThreads.createThread(
            contextId(), {user(1), plain.member()}, {user(1)}, core::Buffer::from("pub"), core::Buffer::from("priv"),
            readableByEverybody(), grantTo(owner->groups->getGroup(groupId))
        );
        for (const auto& [who, id] : std::vector<std::pair<std::string, Identity>>{{"member", x}, {"plain", plain}}) {
            auto session = open(id.privKey);
            auto threads = thread::ThreadApi::create(*session->connection, *session->groups);
            std::vector<std::string> ids;
            auto send = [&] { ids.push_back(threads.sendMessage(threadId, core::Buffer::from("p"), core::Buffer::from("p"), core::Buffer::from("hot"))); };
            timed(f, tag, who + "_first_send", send);
            std::vector<double> sends, gets;
            timed(f, tag, who + "_sends", [&] { for (int i = 0; i < calls; ++i) sends.push_back(ms(send)); });
            timed(f, tag, who + "_gets", [&] { for (int i = 0; i < calls; ++i) gets.push_back(ms([&] { threads.getMessage(ids[1 + i]); })); });
            f.push_back({who + "_send_each_ms", arr(sends)});
            f.push_back({who + "_get_each_ms", arr(gets)});
        }
    });
}
