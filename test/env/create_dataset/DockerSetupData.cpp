#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include <vector>
#include <privmx/utils/Utils.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <Poco/URI.h>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/Config.hpp>
#include <privmx/utils/Logger.hpp>

#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/thread/VarSerializer.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/store/VarSerializer.hpp>
#include <privmx/endpoint/inbox/InboxApi.hpp>
#include <privmx/endpoint/inbox/VarSerializer.hpp>
#include <privmx/endpoint/kvdb/KvdbApi.hpp>
#include <privmx/endpoint/kvdb/VarSerializer.hpp>
#include <privmx/endpoint/group/GroupApi.hpp>
#include <privmx/endpoint/group/VarSerializer.hpp>
#include <privmx/endpoint/search/SearchApi.hpp>
#include <privmx/endpoint/lock/LockApi.hpp>
#include <privmx/endpoint/search/Types.hpp>
#include <privmx/endpoint/search/VarSerializer.hpp>

using namespace std;
using namespace privmx;
using namespace privmx::endpoint;

static core::VarSerializer _serializer = core::VarSerializer({});

// ServerData.ini is read by the e2e tests and ServerData.json by projects outside this repo. One call per
// fixture fills both, so a fixture cannot land in one and be forgotten in the other.
struct DatasetWriter {
    std::ostringstream ini;
    Poco::JSON::Object::Ptr json = new Poco::JSON::Object();
};

// Both artifacts are built in memory and flushed once, so a run that throws leaves the previous files intact.
static void saveDataset(DatasetWriter& out, const string& iniPath, const string& jsonPath) {
    fstream iniFile(iniPath, ios::app);
    iniFile << out.ini.str();
    iniFile.close();
    fstream jsonFile(jsonPath, ios::out | ios::trunc);
    jsonFile << utils::Utils::stringify(out.json, true) << std::endl;
    jsonFile.close();
}

// A created container, carried until its section can be written - which is once its items exist, because the
// container row reports how many there are and when the last one landed.
struct Fixture {
    string name;
    string id;
    core::Buffer publicMeta;
    core::Buffer privateMeta;
};

// Every fixture's metadata is its base name plus one of these suffixes, so call sites spell only the base.
static core::Buffer publicMetaOf(const string& metaBase) {
    return core::Buffer::from(metaBase + "_publicMeta");
}

static core::Buffer privateMetaOf(const string& metaBase) {
    return core::Buffer::from(metaBase + "_privateMeta");
}

static void writeHex(std::ostream& ini, const string& key, const string& value) {
    ini << key << " = " << utils::Hex::from(value) << std::endl;
}

// Opens a section in the ini and the matching object in the json, handing the latter back so the shapes with
// extra fields can add to it.
static Poco::JSON::Object::Ptr beginEntry(
    DatasetWriter& out, const string& name, const Poco::Dynamic::Var& serialized
) {
    out.ini << "[" << name << "]" << std::endl;
    Poco::JSON::Object::Ptr entry = new Poco::JSON::Object();
    entry->set("server_data", serialized);
    out.json->set(name, entry);
    return entry;
}

static void writeUploadedMeta(
    DatasetWriter& out, Poco::JSON::Object::Ptr entry, const string& upPub, const string& upPriv
) {
    writeHex(out.ini, "uploaded_publicMeta_inHex", upPub);
    writeHex(out.ini, "uploaded_privateMeta_inHex", upPriv);
    entry->set("uploaded_publicMeta_inBase64", utils::Base64::from(upPub));
    entry->set("uploaded_privateMeta_inBase64", utils::Base64::from(upPriv));
}

static void writeUploadedData(DatasetWriter& out, Poco::JSON::Object::Ptr entry, const string& upData) {
    writeHex(out.ini, "uploaded_data_inHex", upData);
    entry->set("uploaded_data_inBase64", utils::Base64::from(upData));
}

// Grants and stale groups are on every container type but not on any common base, so this stays a template.
template<typename ContainerT>
static void writeGrants(DatasetWriter& out, const ContainerT& container) {
    out.ini << "groups_count = " << container.groups.size() << std::endl;
    for(size_t i = 0; i < container.groups.size(); ++i) {
        out.ini << "groups_" << i << "_groupId = " << container.groups[i].groupId << std::endl;
        out.ini << "groups_" << i << "_role = " << container.groups[i].role << std::endl;
    }
    out.ini << "staleGroups_count = " << container.staleGroups.size() << std::endl;
    for(size_t i = 0; i < container.staleGroups.size(); ++i) {
        out.ini << "staleGroups_" << i << " = " << container.staleGroups[i] << std::endl;
    }
}

// Common head of every container section: who made it and when.
template<typename ContainerT>
static void writeContainerHead(DatasetWriter& out, const ContainerT& c) {
    out.ini << "contextId = " << c.contextId << std::endl;
    out.ini << "createDate = " << c.createDate << std::endl;
    out.ini << "creator = " << c.creator << std::endl;
    out.ini << "lastModificationDate = " << c.lastModificationDate << std::endl;
    out.ini << "lastModifier = " << c.lastModifier << std::endl;
    out.ini << "version = " << c.version << std::endl;
}

// Common tail: the status the bridge reported and the whole object as the serializer sees it.
template<typename ContainerT>
static void writeStatus(DatasetWriter& out, const ContainerT& c, const Poco::Dynamic::Var& serialized) {
    out.ini << "statusCode = " << c.statusCode << std::endl;
    out.ini << "schemaVersion = " << c.schemaVersion << std::endl;
    out.ini << "JSON_data = " << utils::Utils::stringifyVar(serialized) << std::endl;
}

static Fixture createGroup(
    group::GroupApi& api, const string& name, const string& metaBase, const string& contextId,
    const vector<core::UserWithPubKey>& users, const vector<core::UserWithPubKey>& managers
) {
    LOG_INFO(name + " - create")
    const core::Buffer publicMeta = publicMetaOf(metaBase);
    const core::Buffer privateMeta = privateMetaOf(metaBase);
    const string id = api.createGroup(contextId, users, managers, publicMeta, privateMeta);
    return Fixture{name, id, publicMeta, privateMeta};
}

// `preRotationPubKey` and `removedUserId` are set only for a group the generator rotated.
static void writeGroup(
    DatasetWriter& out, group::GroupApi& api, const Fixture& f,
    const string& preRotationPubKey = "", const string& removedUserId = ""
) {
    const group::Group g = api.getGroup(f.id);
    const Poco::Dynamic::Var serialized = _serializer.serialize(g);
    Poco::JSON::Object::Ptr entry = beginEntry(out, f.name, serialized);
    out.ini << "groupId = " << g.groupId << std::endl;
    out.ini << "contextId = " << g.contextId << std::endl;
    out.ini << "createDate = " << g.createDate << std::endl;
    out.ini << "creator = " << g.creator << std::endl;
    out.ini << "lastModificationDate = " << g.lastModificationDate << std::endl;
    out.ini << "lastModifier = " << g.lastModifier << std::endl;
    out.ini << "publicMetaVersion = " << g.publicMetaVersion << std::endl;
    out.ini << "privateMetaVersion = " << g.privateMetaVersion << std::endl;
    out.ini << "keyVersion = " << g.keyVersion << std::endl;
    out.ini << "rosterVersion = " << g.rosterVersion << std::endl;
    out.ini << "groupPubKey = " << g.groupPubKey << std::endl;
    writeHex(out.ini, "publicMeta_inHex", g.publicMeta.stdString());
    writeHex(out.ini, "privateMeta_inHex", g.privateMeta.stdString());
    if(!preRotationPubKey.empty()) {
        out.ini << "preRotation_groupPubKey = " << preRotationPubKey << std::endl;
        out.ini << "removedUserId = " << removedUserId << std::endl;
        entry->set("preRotation_groupPubKey", preRotationPubKey);
        entry->set("removedUserId", removedUserId);
    }
    out.ini << "statusCode = " << g.statusCode << std::endl;
    out.ini << "schemaVersion = " << g.schemaVersion << std::endl;
    writeUploadedMeta(out, entry, f.publicMeta.stdString(), f.privateMeta.stdString());
}

static Fixture createThread(
    thread::ThreadApi& api, const string& name, const string& metaBase, const string& contextId,
    const vector<core::UserWithPubKey>& users, const vector<core::UserWithPubKey>& managers,
    const vector<core::GroupGrantWithKey>& grants = {}
) {
    LOG_INFO(name + " - create")
    const core::Buffer publicMeta = publicMetaOf(metaBase);
    const core::Buffer privateMeta = privateMetaOf(metaBase);
    const string id = api.createThread(contextId, users, managers, publicMeta, privateMeta, std::nullopt, grants);
    return Fixture{name, id, publicMeta, privateMeta};
}

static void writeThread(DatasetWriter& out, thread::ThreadApi& api, const Fixture& f) {
    const thread::Thread t = api.getThread(f.id);
    const Poco::Dynamic::Var serialized = _serializer.serialize(t);
    Poco::JSON::Object::Ptr entry = beginEntry(out, f.name, serialized);
    writeContainerHead(out, t);
    out.ini << "threadId = " << t.threadId << std::endl;
    out.ini << "lastMsgDate = " << t.lastMsgDate << std::endl;
    writeHex(out.ini, "publicMeta_inHex", t.publicMeta.stdString());
    writeHex(out.ini, "privateMeta_inHex", t.privateMeta.stdString());
    out.ini << "messagesCount = " << t.messagesCount << std::endl;
    writeGrants(out, t);
    writeStatus(out, t, serialized);
    writeUploadedMeta(out, entry, f.publicMeta.stdString(), f.privateMeta.stdString());
}

static Fixture createStore(
    store::StoreApi& api, const string& name, const string& metaBase, const string& contextId,
    const vector<core::UserWithPubKey>& users, const vector<core::UserWithPubKey>& managers,
    const vector<core::GroupGrantWithKey>& grants = {}
) {
    LOG_INFO(name + " - create")
    const core::Buffer publicMeta = publicMetaOf(metaBase);
    const core::Buffer privateMeta = privateMetaOf(metaBase);
    const string id = api.createStore(contextId, users, managers, publicMeta, privateMeta, std::nullopt, grants);
    return Fixture{name, id, publicMeta, privateMeta};
}

static void writeStore(DatasetWriter& out, store::StoreApi& api, const Fixture& f) {
    const store::Store s = api.getStore(f.id);
    const Poco::Dynamic::Var serialized = _serializer.serialize(s);
    Poco::JSON::Object::Ptr entry = beginEntry(out, f.name, serialized);
    writeContainerHead(out, s);
    out.ini << "storeId = " << s.storeId << std::endl;
    out.ini << "lastFileDate = " << s.lastFileDate << std::endl;
    writeHex(out.ini, "publicMeta_inHex", s.publicMeta.stdString());
    writeHex(out.ini, "privateMeta_inHex", s.privateMeta.stdString());
    out.ini << "filesCount = " << s.filesCount << std::endl;
    writeGrants(out, s);
    writeStatus(out, s, serialized);
    writeUploadedMeta(out, entry, f.publicMeta.stdString(), f.privateMeta.stdString());
}

static Fixture createKvdb(
    kvdb::KvdbApi& api, const string& name, const string& metaBase, const string& contextId,
    const vector<core::UserWithPubKey>& users, const vector<core::UserWithPubKey>& managers,
    const vector<core::GroupGrantWithKey>& grants = {}
) {
    LOG_INFO(name + " - create")
    const core::Buffer publicMeta = publicMetaOf(metaBase);
    const core::Buffer privateMeta = privateMetaOf(metaBase);
    const string id = api.createKvdb(contextId, users, managers, publicMeta, privateMeta, std::nullopt, grants);
    return Fixture{name, id, publicMeta, privateMeta};
}

static void writeKvdb(DatasetWriter& out, kvdb::KvdbApi& api, const Fixture& f) {
    const kvdb::Kvdb k = api.getKvdb(f.id);
    const Poco::Dynamic::Var serialized = _serializer.serialize(k);
    Poco::JSON::Object::Ptr entry = beginEntry(out, f.name, serialized);
    writeContainerHead(out, k);
    out.ini << "kvdbId = " << k.kvdbId << std::endl;
    out.ini << "lastEntryDate = " << k.lastEntryDate << std::endl;
    writeHex(out.ini, "publicMeta_inHex", k.publicMeta.stdString());
    writeHex(out.ini, "privateMeta_inHex", k.privateMeta.stdString());
    out.ini << "entries = " << k.entries << std::endl;
    writeGrants(out, k);
    writeStatus(out, k, serialized);
    writeUploadedMeta(out, entry, f.publicMeta.stdString(), f.privateMeta.stdString());
}

static Fixture createInbox(
    inbox::InboxApi& api, const string& name, const string& metaBase, const string& contextId,
    const vector<core::UserWithPubKey>& users, const vector<core::UserWithPubKey>& managers,
    const std::optional<inbox::FilesConfig>& filesConfig = std::nullopt,
    const vector<core::GroupGrantWithKey>& grants = {}
) {
    LOG_INFO(name + " - create")
    const core::Buffer publicMeta = publicMetaOf(metaBase);
    const core::Buffer privateMeta = privateMetaOf(metaBase);
    const string id = api.createInbox(
        contextId, users, managers, publicMeta, privateMeta, filesConfig, std::nullopt, grants
    );
    return Fixture{name, id, publicMeta, privateMeta};
}

static void writeInbox(DatasetWriter& out, inbox::InboxApi& api, const Fixture& f) {
    const inbox::Inbox b = api.getInbox(f.id);
    const Poco::Dynamic::Var serialized = _serializer.serialize(b);
    Poco::JSON::Object::Ptr entry = beginEntry(out, f.name, serialized);
    writeContainerHead(out, b);
    out.ini << "inboxId = " << b.inboxId << std::endl;
    writeHex(out.ini, "publicMeta_inHex", b.publicMeta.stdString());
    writeHex(out.ini, "privateMeta_inHex", b.privateMeta.stdString());
    if(b.filesConfig.has_value()) {
        const auto& fc = b.filesConfig.value();
        out.ini << "filesConfig_minCount = " << fc.minCount << std::endl;
        out.ini << "filesConfig_maxCount = " << fc.maxCount << std::endl;
        out.ini << "filesConfig_maxFileSize = " << fc.maxFileSize << std::endl;
        out.ini << "filesConfig_maxWholeUploadSize = " << fc.maxWholeUploadSize << std::endl;
        entry->set("filesConfig_minCount", fc.minCount);
        entry->set("filesConfig_maxCount", fc.maxCount);
        entry->set("filesConfig_maxFileSize", fc.maxFileSize);
        entry->set("filesConfig_maxWholeUploadSize", fc.maxWholeUploadSize);
    }
    writeGrants(out, b);
    writeStatus(out, b, serialized);
    writeUploadedMeta(out, entry, f.publicMeta.stdString(), f.privateMeta.stdString());
}

static Fixture createSearchIndex(
    search::SearchApi& api, const string& name, const string& metaBase, const string& contextId,
    const vector<core::UserWithPubKey>& users, const vector<core::UserWithPubKey>& managers,
    search::IndexMode mode
) {
    LOG_INFO(name + " - create")
    const core::Buffer publicMeta = publicMetaOf(metaBase);
    const core::Buffer privateMeta = privateMetaOf(metaBase);
    const string id = api.createSearchIndex(contextId, users, managers, publicMeta, privateMeta, mode);
    return Fixture{name, id, publicMeta, privateMeta};
}

// `extras` carries the indexed documents, which only the first index has. The values are Vars because a
// document id is an int64 while its name and content are strings, and the json has to keep those types.
static void writeSearchIndex(
    DatasetWriter& out, search::SearchApi& api, const Fixture& f,
    const vector<std::pair<string, Poco::Dynamic::Var>>& extras = {}
) {
    const search::SearchIndex s = api.getSearchIndex(f.id);
    const Poco::Dynamic::Var serialized = _serializer.serialize(s);
    Poco::JSON::Object::Ptr entry = beginEntry(out, f.name, serialized);
    writeContainerHead(out, s);
    out.ini << "indexId = " << s.indexId << std::endl;
    out.ini << "mode = " << static_cast<int64_t>(s.mode) << std::endl;
    writeHex(out.ini, "publicMeta_inHex", s.publicMeta.stdString());
    writeHex(out.ini, "privateMeta_inHex", s.privateMeta.stdString());
    writeStatus(out, s, serialized);
    writeUploadedMeta(out, entry, f.publicMeta.stdString(), f.privateMeta.stdString());
    for(const auto& extra : extras) {
        out.ini << extra.first << " = " << extra.second.convert<string>() << std::endl;
        entry->set(extra.first, extra.second);
    }
}

// An item is final the moment it is sent, so one call creates it, reads it back and writes both artifacts.
static void addMessage(
    DatasetWriter& out, thread::ThreadApi& api, const string& name, const string& metaBase,
    const string& threadId, const string& data
) {
    LOG_INFO(name + " - create")
    const core::Buffer publicMeta = publicMetaOf(metaBase);
    const core::Buffer privateMeta = privateMetaOf(metaBase);
    const string id = api.sendMessage(threadId, publicMeta, privateMeta, core::Buffer::from(data));
    const thread::Message m = api.getMessage(id);
    const Poco::Dynamic::Var serialized = _serializer.serialize(m);
    Poco::JSON::Object::Ptr entry = beginEntry(out, name, serialized);
    out.ini << "info_threadId = " << m.info.threadId << std::endl;
    out.ini << "info_messageId = " << m.info.messageId << std::endl;
    out.ini << "info_createDate = " << m.info.createDate << std::endl;
    out.ini << "info_author = " << m.info.author << std::endl;
    writeHex(out.ini, "publicMeta_inHex", m.publicMeta.stdString());
    writeHex(out.ini, "privateMeta_inHex", m.privateMeta.stdString());
    writeHex(out.ini, "data_inHex", m.data.stdString());
    out.ini << "authorPubKey = " << m.authorPubKey << std::endl;
    writeStatus(out, m, serialized);
    writeUploadedMeta(out, entry, publicMeta.stdString(), privateMeta.stdString());
    writeUploadedData(out, entry, data);
}

static void addFile(
    DatasetWriter& out, store::StoreApi& api, const string& name, const string& metaBase,
    const string& storeId, const string& data
) {
    LOG_INFO(name + " - create")
    const string publicMeta = metaBase + "_publicMeta";
    const string privateMeta = metaBase + "_privateMeta";
    const int64_t handle = api.createFile(
        storeId, core::Buffer::from(publicMeta), core::Buffer::from(privateMeta), data.size()
    );
    api.writeToFile(handle, core::Buffer::from(data));
    const store::File f = api.getFile(api.closeFile(handle));
    const Poco::Dynamic::Var serialized = _serializer.serialize(f);
    Poco::JSON::Object::Ptr entry = beginEntry(out, name, serialized);
    out.ini << "info_storeId = " << f.info.storeId << std::endl;
    out.ini << "info_fileId = " << f.info.fileId << std::endl;
    out.ini << "info_createDate = " << f.info.createDate << std::endl;
    out.ini << "info_author = " << f.info.author << std::endl;
    writeHex(out.ini, "publicMeta_inHex", f.publicMeta.stdString());
    writeHex(out.ini, "privateMeta_inHex", f.privateMeta.stdString());
    out.ini << "size = " << f.size << std::endl;
    out.ini << "authorPubKey = " << f.authorPubKey << std::endl;
    writeStatus(out, f, serialized);
    writeUploadedMeta(out, entry, publicMeta, privateMeta);
    out.ini << "uploaded_size = " << data.size() << std::endl;
    entry->set("uploaded_size", data.size());
    writeUploadedData(out, entry, data);
}

static void addKvdbEntry(
    DatasetWriter& out, kvdb::KvdbApi& api, const string& name, const string& metaBase,
    const string& kvdbId, const string& key, const string& data
) {
    LOG_INFO(name + " - create")
    const core::Buffer publicMeta = publicMetaOf(metaBase);
    const core::Buffer privateMeta = privateMetaOf(metaBase);
    api.setEntry(kvdbId, key, publicMeta, privateMeta, core::Buffer::from(data), 0);
    const kvdb::KvdbEntry e = api.getEntry(kvdbId, key);
    const Poco::Dynamic::Var serialized = _serializer.serialize(e);
    Poco::JSON::Object::Ptr entry = beginEntry(out, name, serialized);
    out.ini << "info_kvdbId = " << e.info.kvdbId << std::endl;
    out.ini << "info_key = " << e.info.key << std::endl;
    out.ini << "info_createDate = " << e.info.createDate << std::endl;
    out.ini << "info_author = " << e.info.author << std::endl;
    writeHex(out.ini, "publicMeta_inHex", e.publicMeta.stdString());
    writeHex(out.ini, "privateMeta_inHex", e.privateMeta.stdString());
    writeHex(out.ini, "data_inHex", e.data.stdString());
    out.ini << "authorPubKey = " << e.authorPubKey << std::endl;
    writeStatus(out, e, serialized);
    writeUploadedMeta(out, entry, publicMeta.stdString(), privateMeta.stdString());
    writeUploadedData(out, entry, data);
}

// What was uploaded alongside an inbox entry, in the order the entry carries them.
struct UploadedEntryFile {
    string publicMeta;
    string privateMeta;
    string data;
};

// These files take their payload from the same base name as their metadata.
static UploadedEntryFile entryFile(const string& metaBase) {
    return UploadedEntryFile{metaBase + "_publicMeta", metaBase + "_privateMeta", metaBase};
}

// Reads the entry back as the newest one in the inbox, which it is until the next send.
static void addInboxEntry(
    DatasetWriter& out, inbox::InboxApi& api, const string& name, const string& inboxId, const string& data,
    const vector<UploadedEntryFile>& upFiles = {}
) {
    LOG_INFO(name + " - create")
    vector<int64_t> fileHandles;
    for(const auto& upFile : upFiles) {
        fileHandles.push_back(api.createFileHandle(
            core::Buffer::from(upFile.publicMeta), core::Buffer::from(upFile.privateMeta), upFile.data.size()
        ));
    }
    const int64_t entryHandle = api.prepareEntry(inboxId, core::Buffer::from(data), fileHandles, std::nullopt);
    for(size_t i = 0; i < upFiles.size(); ++i) {
        api.writeToFile(entryHandle, fileHandles[i], core::Buffer::from(upFiles[i].data));
    }
    api.sendEntry(entryHandle);
    const inbox::InboxEntry e =
        api.listEntries(inboxId, {.skip=0, .limit=1, .sortOrder="desc"}).readItems[0];
    const Poco::Dynamic::Var serialized = _serializer.serialize(e);
    Poco::JSON::Object::Ptr entry = beginEntry(out, name, serialized);
    out.ini << "entryId = " << e.entryId << std::endl;
    out.ini << "inboxId = " << e.inboxId << std::endl;
    writeHex(out.ini, "data_inHex", e.data.stdString());
    out.ini << "authorPubKey = " << e.authorPubKey << std::endl;
    out.ini << "createDate = " << e.createDate << std::endl;
    out.ini << "statusCode = " << e.statusCode << std::endl;
    out.ini << "schemaVersion = " << e.schemaVersion << std::endl;
    for(size_t i = 0; i < e.files.size(); ++i) {
        const string p = "file_" + std::to_string(i) + "_";
        const auto& f = e.files[i];
        out.ini << p << "info_storeId = " << f.info.storeId << std::endl;
        out.ini << p << "info_fileId = " << f.info.fileId << std::endl;
        out.ini << p << "info_createDate = " << f.info.createDate << std::endl;
        out.ini << p << "info_author = " << f.info.author << std::endl;
        out.ini << p << "authorPubKey = " << f.authorPubKey << std::endl;
        out.ini << p << "statusCode = " << f.statusCode << std::endl;
        out.ini << p << "schemaVersion = " << f.schemaVersion << std::endl;
        writeHex(out.ini, p + "publicMeta_inHex", f.publicMeta.stdString());
        writeHex(out.ini, p + "privateMeta_inHex", f.privateMeta.stdString());
        out.ini << p << "size = " << f.size << std::endl;
    }
    out.ini << "JSON_data = " << utils::Utils::stringifyVar(serialized) << std::endl;
    for(size_t i = 0; i < upFiles.size(); ++i) {
        const string p = "uploaded_file_" + std::to_string(i) + "_";
        writeHex(out.ini, p + "publicMeta_inHex", upFiles[i].publicMeta);
        writeHex(out.ini, p + "privateMeta_inHex", upFiles[i].privateMeta);
        out.ini << p << "size = " << upFiles[i].data.size() << std::endl;
        writeHex(out.ini, p + "data_inHex", upFiles[i].data);
        entry->set(p + "publicMeta_inBase64", utils::Base64::from(upFiles[i].publicMeta));
        entry->set(p + "privateMeta_inBase64", utils::Base64::from(upFiles[i].privateMeta));
        entry->set(p + "size", upFiles[i].data.size());
        entry->set(p + "data_inBase64", utils::Base64::from(upFiles[i].data));
    }
    writeUploadedData(out, entry, data);
}

// A grant carrying both the key and the epoch is treated as complete, so the module apis resolve it without
// holding a GroupApi of their own.
static core::GroupGrantWithKey groupGrant(const group::Group& g) {
    return core::GroupGrantWithKey{
        .groupId = g.groupId, .role = "user", .groupPubKey = g.groupPubKey, .groupEpoch = g.keyVersion
    };
}

int main() {
    char * envVal = getenv("DOCKER_BRIDGE_PORT");
    std::string dockerPort = "";
    if (envVal != NULL) {
        dockerPort = std::string(envVal);
    } else {
        std::cout << "system variable DOCKER_BRIDGE_PORT not set" << std::endl;
        return -1;
    }

    auto iniFilePath = "ServerData.ini";
    auto iniFileJSONPath = "ServerData.json";
    try {
        Poco::Util::IniFileConfiguration::Ptr reader = new Poco::Util::IniFileConfiguration("ServerData.ini");

        const string user_1_PrivKey = reader->getString("Login.user_1_privKey");
        const string user_1_PubKey = reader->getString("Login.user_1_pubKey");
        const string user_1_Id = reader->getString("Login.user_1_id");
        const string user_2_PrivKey = reader->getString("Login.user_2_privKey");
        const string user_2_PubKey = reader->getString("Login.user_2_pubKey");
        const string user_2_Id = reader->getString("Login.user_2_id");
        const string user_3_PrivKey = reader->getString("Login.user_3_privKey");
        const string user_3_PubKey = reader->getString("Login.user_3_pubKey");
        const string user_3_Id = reader->getString("Login.user_3_id");
        const string solution = reader->getString("Login.solutionId");
        const string platformUrl = reader->getString("Login.instanceUrl");
        Poco::URI tmp = Poco::URI(platformUrl);
        std::string url = "http://" + tmp.getHost() + ":" + dockerPort + tmp.getPath();

        const string context_1_Id = reader->getString("Context_1.contextId");
        const string context_2_Id = reader->getString("Context_2.contextId");

        endpoint::core::Connection connection = endpoint::core::Connection::connect(user_1_PrivKey, solution, url);
        endpoint::thread::ThreadApi threadApi = endpoint::thread::ThreadApi::create(connection);
        endpoint::store::StoreApi storeApi = endpoint::store::StoreApi::create(connection);
        endpoint::inbox::InboxApi inboxApi = endpoint::inbox::InboxApi::create(connection, threadApi, storeApi);
        endpoint::kvdb::KvdbApi kvdbApi = endpoint::kvdb::KvdbApi::create(connection);
        endpoint::group::GroupApi groupApi = endpoint::group::GroupApi::create(connection);
        endpoint::lock::LockApi lockApi = endpoint::lock::LockApi::create(connection);
        endpoint::search::SearchApi searchApi = endpoint::search::SearchApi::create(connection, storeApi, kvdbApi, lockApi);
        const std::vector<endpoint::core::UserWithPubKey> users_1 = {
            endpoint::core::UserWithPubKey{.userId=user_1_Id, .pubKey=user_1_PubKey}
        };
        const std::vector<endpoint::core::UserWithPubKey> users_1_2 = {
            endpoint::core::UserWithPubKey{.userId=user_1_Id, .pubKey=user_1_PubKey},
            endpoint::core::UserWithPubKey{.userId=user_2_Id, .pubKey=user_2_PubKey}
        };
        const std::vector<endpoint::core::UserWithPubKey> users_1_2_3 = {
            endpoint::core::UserWithPubKey{.userId=user_1_Id, .pubKey=user_1_PubKey},
            endpoint::core::UserWithPubKey{.userId=user_2_Id, .pubKey=user_2_PubKey},
            endpoint::core::UserWithPubKey{.userId=user_3_Id, .pubKey=user_3_PubKey}
        };
        DatasetWriter out;
        
        // Context 1
        const Fixture thread_1 = createThread(
            threadApi, "Thread_1", "test_thread_1", context_1_Id, users_1, users_1
        );
        addMessage(out, threadApi, "Message_1", "test_message_1", thread_1.id, "message_from_sendMessage");
        addMessage(out, threadApi, "Message_2", "test_message_2", thread_1.id, "message_from_sendMessage");
        writeThread(out, threadApi, thread_1);
        const Fixture thread_2 = createThread(
            threadApi, "Thread_2", "test_thread_2", context_1_Id, users_1_2, users_1_2
        );
        writeThread(out, threadApi, thread_2);
        const Fixture thread_3 = createThread(
            threadApi, "Thread_3", "test_thread_3", context_1_Id, users_1_2, users_1
        );
        writeThread(out, threadApi, thread_3);

        const Fixture store_1 = createStore(storeApi, "Store_1", "test_store_1", context_1_Id, users_1, users_1);
        addFile(out, storeApi, "File_1", "test_fileData_1", store_1.id, "test_fileData_1");
        addFile(out, storeApi, "File_2", "test_fileData_2", store_1.id, "test_fileData_2_extraText");
        writeStore(out, storeApi, store_1);
        const Fixture store_2 = createStore(
            storeApi, "Store_2", "test_store_2", context_1_Id, users_1_2, users_1_2
        );
        writeStore(out, storeApi, store_2);
        const Fixture store_3 = createStore(
            storeApi, "Store_3", "test_store_3", context_1_Id, users_1_2, users_1
        );
        writeStore(out, storeApi, store_3);

        const Fixture inbox_1 = createInbox(inboxApi, "Inbox_1", "test_inbox_1", context_1_Id, users_1, users_1);
        addInboxEntry(
            out, inboxApi, "Entry_1", inbox_1.id, "message_from_inboxSendCommit_1",
            {entryFile("test_entry_1_FileData_0"), entryFile("test_entry_1_FileData_1")}
        );
        addInboxEntry(out, inboxApi, "Entry_2", inbox_1.id, "message_from_inboxSendCommit_2");
        writeInbox(out, inboxApi, inbox_1);
        const Fixture inbox_2 = createInbox(
            inboxApi, "Inbox_2", "test_inbox_2", context_1_Id, users_1_2, users_1_2,
            inbox::FilesConfig{.minCount=0, .maxCount=2, .maxFileSize=1024*1024*128, .maxWholeUploadSize=1024*1024*255}
        );
        writeInbox(out, inboxApi, inbox_2);
        const Fixture inbox_3 = createInbox(
            inboxApi, "Inbox_3", "test_inbox_3", context_1_Id, users_1_2, users_1
        );
        writeInbox(out, inboxApi, inbox_3);

        const Fixture kvdb_1 = createKvdb(kvdbApi, "Kvdb_1", "test_kvdb_1", context_1_Id, users_1, users_1);
        addKvdbEntry(
            out, kvdbApi, "KvdbEntry_1", "test_kvdb_entry_1", kvdb_1.id, "kvdb_entry_key_1", "kvdb_entry_value_1"
        );
        addKvdbEntry(
            out, kvdbApi, "KvdbEntry_2", "test_kvdb_entry_2", kvdb_1.id, "kvdb_entry_key_2", "kvdb_entry_value_2"
        );
        writeKvdb(out, kvdbApi, kvdb_1);
        const Fixture kvdb_2 = createKvdb(kvdbApi, "Kvdb_2", "test_kvdb_2", context_1_Id, users_1_2, users_1_2);
        writeKvdb(out, kvdbApi, kvdb_2);
        const Fixture kvdb_3 = createKvdb(kvdbApi, "Kvdb_3", "test_kvdb_3", context_1_Id, users_1_2, users_1);
        writeKvdb(out, kvdbApi, kvdb_3);

        const Fixture searchIndex_1 = createSearchIndex(
            searchApi, "SearchIndex_1", "test_search_index_1", context_1_Id, users_1, users_1,
            search::IndexMode::WITH_CONTENT
        );
        LOG_INFO("SearchIndex_1 - adding documents")
        const int64_t indexHandle_1 = searchApi.openSearchIndex(searchIndex_1.id);
        const int64_t doc_1_id = searchApi.addDocument(indexHandle_1, "doc-1", "Ala ma kota");
        const int64_t doc_2_id = searchApi.addDocument(indexHandle_1, "doc-2", "Ola ma kota");
        searchApi.closeSearchIndex(indexHandle_1);
        writeSearchIndex(out, searchApi, searchIndex_1, {
            {"doc_1_id", doc_1_id},
            {"doc_1_name", "doc-1"},
            {"doc_1_content", "Ala ma kota"},
            {"doc_2_id", doc_2_id},
            {"doc_2_name", "doc-2"},
            {"doc_2_content", "Ola ma kota"},
            {"docs_common_content_part", "ma kota"}
        });
        const Fixture searchIndex_2 = createSearchIndex(
            searchApi, "SearchIndex_2", "test_search_index_2", context_1_Id, users_1_2, users_1_2,
            search::IndexMode::WITHOUT_CONTENT
        );
        writeSearchIndex(out, searchApi, searchIndex_2);
        const Fixture searchIndex_3 = createSearchIndex(
            searchApi, "SearchIndex_3", "test_search_index_3", context_1_Id, users_1_2, users_1,
            search::IndexMode::WITH_CONTENT
        );
        writeSearchIndex(out, searchApi, searchIndex_3);

        const Fixture group_1 = createGroup(groupApi, "Group_1", "test_group_1", context_1_Id, users_1, users_1);
        writeGroup(out, groupApi, group_1);
        const Fixture group_2 = createGroup(
            groupApi, "Group_2", "test_group_2", context_1_Id, users_1_2, users_1
        );
        writeGroup(out, groupApi, group_2);
        const Fixture group_3 = createGroup(
            groupApi, "Group_3", "test_group_3", context_1_Id, users_1_2_3, users_1
        );
        writeGroup(out, groupApi, group_3);

        // Context_2 
        const Fixture group_4 = createGroup(
            groupApi, "Group_4", "test_group_4", context_2_Id, users_1_2, users_1
        );
        const Fixture group_5 = createGroup(
            groupApi, "Group_5", "test_group_5", context_2_Id, users_1_2_3, users_1
        );
        const Fixture group_6 = createGroup(
            groupApi, "Group_6", "test_group_6", context_2_Id, users_1_2_3, users_1
        );
        const Fixture group_7 = createGroup(groupApi, "Group_7", "test_group_7", context_2_Id, users_1, users_1);
        const group::Group group_5_beforeRotation = groupApi.getGroup(group_5.id);
        const vector<core::GroupGrantWithKey> group_5_grant = {groupGrant(group_5_beforeRotation)};
        const vector<core::GroupGrantWithKey> group_7_grant = {groupGrant(groupApi.getGroup(group_7.id))};
        const vector<core::GroupGrantWithKey> group_4_and_6_grant = {
            groupGrant(groupApi.getGroup(group_4.id)), groupGrant(groupApi.getGroup(group_6.id))
        };

        const Fixture thread_4 = createThread(
            threadApi, "Thread_4", "test_thread_4", context_2_Id, users_1, users_1, group_4_and_6_grant
        );
        addMessage(
            out, threadApi, "Message_3", "test_message_3", thread_4.id, "message_readable_through_a_group"
        );
        addMessage(
            out, threadApi, "Message_4", "test_message_4", thread_4.id, "second_message_readable_through_a_group"
        );
        writeThread(out, threadApi, thread_4);
        const Fixture store_4 = createStore(
            storeApi, "Store_4", "test_store_4", context_2_Id, users_1, users_1, group_4_and_6_grant
        );
        addFile(out, storeApi, "File_3", "test_fileData_3", store_4.id, "file_readable_through_a_group");
        addFile(out, storeApi, "File_4", "test_fileData_4", store_4.id, "second_file_readable_through_a_group");
        writeStore(out, storeApi, store_4);
        const Fixture kvdb_4 = createKvdb(
            kvdbApi, "Kvdb_4", "test_kvdb_4", context_2_Id, users_1, users_1, group_4_and_6_grant
        );
        addKvdbEntry(
            out, kvdbApi, "KvdbEntry_3", "test_kvdb_entry_3", kvdb_4.id, "kvdb_entry_key_3",
            "entry_readable_through_a_group"
        );
        addKvdbEntry(
            out, kvdbApi, "KvdbEntry_4", "test_kvdb_entry_4", kvdb_4.id, "kvdb_entry_key_4",
            "second_entry_readable_through_a_group"
        );
        writeKvdb(out, kvdbApi, kvdb_4);
        const Fixture inbox_4 = createInbox(
            inboxApi, "Inbox_4", "test_inbox_4", context_2_Id, users_1, users_1, std::nullopt,
            group_4_and_6_grant
        );
        addInboxEntry(out, inboxApi, "Entry_3", inbox_4.id, "inbox_entry_readable_through_a_group");
        addInboxEntry(out, inboxApi, "Entry_4", inbox_4.id, "second_inbox_entry_readable_through_a_group");
        writeInbox(out, inboxApi, inbox_4);
        const Fixture thread_6 = createThread(
            threadApi, "Thread_6", "test_thread_6", context_2_Id, users_1_2, users_1, group_7_grant
        );
        addMessage(
            out, threadApi, "Message_6", "test_message_6", thread_6.id, "message_readable_through_a_direct_key"
        );
        writeThread(out, threadApi, thread_6);
        const Fixture store_5 = createStore(
            storeApi, "Store_5", "test_store_5", context_2_Id, users_1_2, users_1, group_7_grant
        );
        addFile(out, storeApi, "File_5", "test_fileData_5", store_5.id, "file_readable_through_a_direct_key");
        writeStore(out, storeApi, store_5);
        const Fixture kvdb_5 = createKvdb(
            kvdbApi, "Kvdb_5", "test_kvdb_5", context_2_Id, users_1_2, users_1, group_7_grant
        );
        addKvdbEntry(
            out, kvdbApi, "KvdbEntry_5", "test_kvdb_entry_5", kvdb_5.id, "kvdb_entry_key_5",
            "entry_readable_through_a_direct_key"
        );
        writeKvdb(out, kvdbApi, kvdb_5);
        const Fixture inbox_5 = createInbox(
            inboxApi, "Inbox_5", "test_inbox_5", context_2_Id, users_1_2, users_1, std::nullopt, group_7_grant
        );
        addInboxEntry(out, inboxApi, "Entry_5", inbox_5.id, "inbox_entry_readable_through_a_direct_key");
        writeInbox(out, inboxApi, inbox_5);

        const Fixture thread_5 = createThread(
            threadApi, "Thread_5", "test_thread_5", context_2_Id, users_1, users_1, group_5_grant
        );
        addMessage(
            out, threadApi, "Message_5", "test_message_5", thread_5.id, "message_written_before_the_rotation"
        );
        LOG_INFO("Group_5 - remove user_3, taking the group to epoch 2")
        groupApi.removeGroupMembers(group_5.id, {user_3_Id});

        writeThread(out, threadApi, thread_5);
        writeGroup(out, groupApi, group_4);
        writeGroup(out, groupApi, group_5, group_5_beforeRotation.groupPubKey, user_3_Id);
        writeGroup(out, groupApi, group_6);
        writeGroup(out, groupApi, group_7);

        // Write data
        Poco::JSON::Object::Ptr data_login = new Poco::JSON::Object();
        data_login->set("user_1_privKey", user_1_PrivKey);
        data_login->set("user_1_pubKey", user_1_PubKey);
        data_login->set("user_1_id", user_1_Id);
        data_login->set("user_2_privKey", user_2_PrivKey);
        data_login->set("user_2_pubKey", user_2_PubKey);
        data_login->set("user_2_id", user_2_Id);
        data_login->set("user_3_privKey", user_3_PrivKey);
        data_login->set("user_3_pubKey", user_3_PubKey);
        data_login->set("user_3_id", user_3_Id);
        data_login->set("solutionId", solution);
        data_login->set("instanceUrl", platformUrl);
        out.json->set("Login", data_login);
        Poco::JSON::Object::Ptr data_context_1 = new Poco::JSON::Object();
        data_context_1->set("contextId", context_1_Id);
        out.json->set("Context_1", data_context_1);
        Poco::JSON::Object::Ptr data_context_2 = new Poco::JSON::Object();
        data_context_2->set("contextId", context_2_Id);
        out.json->set("Context_2", data_context_2);

        LOG_INFO("Writing data to ini and json files")
        saveDataset(out, iniFilePath, iniFileJSONPath);

    } catch (const endpoint::core::Exception& e) {
        cerr << e.getFull() << endl;
        return -1;
    } catch (const exception& e) {
        cerr << e.what() << endl;
        return -1;
    } catch (...) {
        cerr << "Error" << endl;
        return -1;
    }
}