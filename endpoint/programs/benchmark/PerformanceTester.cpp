#include <optional>
#include <iostream>
#include <chrono>

#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/inbox/InboxApi.hpp>
#include <privmx/endpoint/core/Buffer.hpp>
#include <functional>
#include <Poco/Util/IniFileConfiguration.h>

using namespace privmx::endpoint;
using namespace std::chrono;
using namespace std::placeholders;

struct Times {
    std::string _label; int min; int max; int total; uint64_t startPoint; int _repeats; bool _printToMd;

    Times(const std::string& label, int repeats, bool printToMd = false): _label(label), min(9999999), max(-1), total(0), startPoint(0), _repeats(repeats), _printToMd(printToMd) {}
    void addStartPoint() {
        startPoint = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    }
    void addElapsedPoint() {
        int elapsed = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count() - startPoint;
        total += elapsed;
        min = std::min(min, elapsed);
        max = std::max(max, elapsed);
    }
    void print() {
        if (_printToMd) {
            printf("|%s\t|%d\t|%d\t|%d\n", _label.c_str(), min, max, (int)(total/ _repeats));
        } else {
            printf("[%s] min: %d, max: %d, avg: %d\n", _label.c_str(), min, max, (int)(total/ _repeats));
        }
    }
    void invoke(const std::string& id,     const privmx::endpoint::core::Buffer& pub,     const privmx::endpoint::core::Buffer& priv, const privmx::endpoint::core::Buffer& data, std::function<void(
                const std::string&,     const privmx::endpoint::core::Buffer&,         const privmx::endpoint::core::Buffer&,         const privmx::endpoint::core::Buffer&        )>  func) {
        for (int i = 0; i < _repeats; ++i) {
            addStartPoint();
            func(id, pub, priv, data);
            addElapsedPoint();
        }
        print();
    }
    void invoke(const std::string& id1, std::function<void(const std::string&)>  func) {
        for (int i = 0; i < _repeats; ++i) {
            addStartPoint();
            func(id1);
            addElapsedPoint();
        }
        print();
    }
};

int main() {
    // the values below should be replaced by the ones corresponding to your Brigde Server instance.
    
    //form INI
    auto iniFile = std::getenv("INI_FILE_PATH");
    Poco::Util::IniFileConfiguration::Ptr reader = new Poco::Util::IniFileConfiguration(iniFile);
    const std::string userPrivKey = reader->getString("Login.user_1_privKey");
    const std::string userPubKey = reader->getString("Login.user_1_pubKey");
    const std::string userId = reader->getString("Login.user_1_id");
    const std::string solutionId = reader->getString("Login.solutionId");
    auto env_platformUrl = std::getenv("PLATFORM_URL");
    const std::string platformUrl = env_platformUrl == NULL ? reader->getString("Login.instanceUrl") : ("http://" + std::string(env_platformUrl) + "/");
    int repeats = 100;
    bool printToMd = true;
    
    // setup some defaults
    core::PagingQuery defaultListQuery = {.skip = 0, .limit = 1, .sortOrder = "desc"};
    std::vector<core::UserWithPubKey> users;
    users.push_back({.userId = userId, .pubKey = userPubKey});
    auto emptyData {privmx::endpoint::core::Buffer::from("")};
    auto msgData {privmx::endpoint::core::Buffer::from("message")};
    auto fileData1MB {privmx::endpoint::core::Buffer::from(std::string(1024 * 1000, 's'))};
    std::string oneKbString(1024, 's');
    
    // initialize Endpoint connection and Threads API
    auto connection {core::Connection::connect(userPrivKey, solutionId, platformUrl)};
    auto threadApi {thread::ThreadApi::create(connection)};
    auto storeApi {store::StoreApi::create(connection)};
    auto inboxApi {inbox::InboxApi::create(connection, threadApi, storeApi)};
    auto contextsList = connection.listContexts({.skip=0, .limit=1, .sortOrder="asc"});
    if(contextsList.totalAvailable == 0) {
        throw;
    }
    auto contexts = contextsList.readItems;
    const auto context = contextsList.readItems[0];
    const std::string contextId = contexts[0].contextId;

    // setup for test
    auto threadId {threadApi.createThread(contextId, users, users, emptyData, emptyData)};
    auto storeId {storeApi.createStore(contextId, users, users, emptyData, emptyData)};
    auto inboxId {inboxApi.createInbox(contextId, users, users, emptyData, emptyData, std::nullopt)};
    auto msgIdToGet {threadApi.sendMessage(threadId, emptyData, emptyData, msgData)};
    
    // fileId to get
    auto fileHandle {storeApi.createFile(storeId, emptyData, emptyData, fileData1MB.size())};
    storeApi.writeToFile(fileHandle, fileData1MB);
    auto fileIdToGet {storeApi.closeFile(fileHandle)};

    // inboxEntryId to get
    auto entryFileHandle {inboxApi.createFileHandle(emptyData, emptyData, fileData1MB.size())};
    std::vector<int64_t> files {}; files.push_back(entryFileHandle);
    auto entryHandle {inboxApi.prepareEntry(inboxId, msgData, files)};
    inboxApi.writeToFile(entryHandle, entryFileHandle, fileData1MB);
    inboxApi.sendEntry(entryHandle);
    auto inboxEntryId {inboxApi.listEntries(inboxId, defaultListQuery).readItems[0].entryId};
    
    // benchmarks
    Times("getMessage", repeats, printToMd).invoke(threadId, emptyData, emptyData, msgData, 
        [&](const std::string& id, const privmx::endpoint::core::Buffer& pub, const privmx::endpoint::core::Buffer& priv, const privmx::endpoint::core::Buffer& data) { return threadApi.sendMessage(id, pub, priv, data); }
    );
    Times("sendMessage", repeats, printToMd).invoke(msgIdToGet, 
        [&](const std::string& msgId) { return threadApi.getMessage(msgId); }
    );
    Times("readFromFile", repeats, printToMd).invoke(fileIdToGet, [&](const std::string& fileId) {
        auto handle = storeApi.openFile(fileId);
        storeApi.readFromFile(handle, fileData1MB.size()); 
    });
    Times("writeToFile", repeats, printToMd).invoke("not_used", [&](const std::string& fileId) {
        auto fileHandle {storeApi.createFile(storeId, emptyData, emptyData, fileData1MB.size())};
        storeApi.writeToFile(fileHandle, fileData1MB);
        storeApi.closeFile(fileHandle);
    });
    Times("readEntry", repeats, printToMd).invoke(inboxEntryId, [&](const std::string& entryId) {
        auto entry {inboxApi.readEntry(entryId)};
        for (auto file: entry.files) {
            auto fHandle {inboxApi.openFile(file.info.fileId)};
            inboxApi.readFromFile(fHandle, fileData1MB.size());
        }
    });
    Times("sendEntry", repeats, printToMd).invoke(inboxEntryId, [&](const std::string& entryId) {
        auto entryFileHandle {inboxApi.createFileHandle(emptyData, emptyData, fileData1MB.size())};
        std::vector<int64_t> files {}; files.push_back(entryFileHandle);
        auto entryHandle {inboxApi.prepareEntry(inboxId, msgData, files)};
        inboxApi.writeToFile(entryHandle, entryFileHandle, fileData1MB);
        inboxApi.sendEntry(entryHandle);
    });

    return 0;
}

//start: 16:35 - 17:15
//start: 10:10 - 12:00