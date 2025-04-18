#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include <vector>
#include <string_view>
#include <privmx/utils/Utils.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <Poco/URI.h>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/Config.hpp>

#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/thread/ThreadVarSerializer.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/store/StoreVarSerializer.hpp>
#include <privmx/endpoint/inbox/InboxApi.hpp>
#include <privmx/endpoint/inbox/InboxVarSerializer.hpp>

using namespace std;
using namespace privmx;
using namespace privmx::endpoint;

static vector<string_view> getParamsList(int argc, char* argv[]) {
    vector<string_view> args(argv + 1, argv + argc);
    return args;
}
static string readFile(const string filePath) {
    // string homeDir{getenv("HOME")};
    // string fName{"testImg.png"};
    // string fPath{homeDir + "/" + fName};
    ifstream input(filePath, ios::binary);
    stringstream strStream;
    strStream << input.rdbuf();
    return strStream.str();
}

int main(int argc, char** argv) {
    char * envVal = getenv("DOCKER_PORT");
    std::string dockerPort = "";
    if (envVal != NULL) {
        dockerPort = std::string(envVal);
    } else {
        std::cout << "system variable DOCKER_PORT not set" << std::endl;
        return -1;
    }
    endpoint::core::VarSerializer _serializer = endpoint::core::VarSerializer({});

    auto params = getParamsList(argc, argv);
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
        const std::vector<endpoint::core::UserWithPubKey> users_1 = {
            endpoint::core::UserWithPubKey{.userId=user_1_Id, .pubKey=user_1_PubKey}
        };
        const std::vector<endpoint::core::UserWithPubKey> users_1_2 = {
            endpoint::core::UserWithPubKey{.userId=user_1_Id, .pubKey=user_1_PubKey},
            endpoint::core::UserWithPubKey{.userId=user_2_Id, .pubKey=user_2_PubKey}
        };

        //thread_1
        auto thread_1_publicMeta = endpoint::core::Buffer::from("test_thread_1_publicMeta");
        auto thread_1_privateMeta = endpoint::core::Buffer::from("test_thread_1_privateMeta");
        auto thread_1_id = threadApi.createThread(
            context_1_Id,
            users_1,
            users_1,
            thread_1_publicMeta,
            thread_1_privateMeta
        );
        //thread_2
        auto thread_2_publicMeta = endpoint::core::Buffer::from("test_thread_2_publicMeta");
        auto thread_2_privateMeta = endpoint::core::Buffer::from("test_thread_2_privateMeta");
        auto thread_2_id = threadApi.createThread(
            context_1_Id,
            users_1_2,
            users_1_2,
            thread_2_publicMeta,
            thread_2_privateMeta
        );
        //thread_3
        auto thread_3_publicMeta = endpoint::core::Buffer::from("test_thread_3_publicMeta");
        auto thread_3_privateMeta = endpoint::core::Buffer::from("test_thread_3_privateMeta");
        auto thread_3_id = threadApi.createThread(
            context_1_Id,
            users_1_2,
            users_1,
            thread_3_publicMeta,
            thread_3_privateMeta
        );
        //store_1
        auto store_1_publicMeta = endpoint::core::Buffer::from("test_store_1_publicMeta");
        auto store_1_privateMeta = endpoint::core::Buffer::from("test_store_1_privateMeta");
        auto store_1_id = storeApi.createStore(
            context_1_Id,
            users_1,
            users_1,
            store_1_publicMeta,
            store_1_privateMeta
        );
        //store_2
        auto store_2_publicMeta = endpoint::core::Buffer::from("test_store_2_publicMeta");
        auto store_2_privateMeta = endpoint::core::Buffer::from("test_store_2_privateMeta");
        auto store_2_id = storeApi.createStore(
            context_1_Id,
            users_1_2,
            users_1_2,
            store_2_publicMeta,
            store_2_privateMeta
        );
        //store_3
        auto store_3_publicMeta = endpoint::core::Buffer::from("test_store_3_publicMeta");
        auto store_3_privateMeta = endpoint::core::Buffer::from("test_store_3_privateMeta");
        auto store_3_id = storeApi.createStore(
            context_1_Id,
            users_1_2,
            users_1,
            store_3_publicMeta,
            store_3_privateMeta
        );
        //inbox_1
        auto inbox_1_publicMeta = endpoint::core::Buffer::from("test_inbox_1_publicMeta");
        auto inbox_1_privateMeta = endpoint::core::Buffer::from("test_inbox_1_privateMeta");
        auto inbox_1_id = inboxApi.createInbox(
            context_1_Id,
            users_1,
            users_1,
            inbox_1_publicMeta,
            inbox_1_privateMeta,
            std::nullopt
        );
        //inbox_2
        auto inbox_2_publicMeta = endpoint::core::Buffer::from("test_inbox_2_publicMeta");
        auto inbox_2_privateMeta = endpoint::core::Buffer::from("test_inbox_2_privateMeta");
        auto inbox_2_id = inboxApi.createInbox(
            context_1_Id,
            users_1_2,
            users_1_2,
            inbox_2_publicMeta,
            inbox_2_privateMeta,
            inbox::FilesConfig{.minCount=0, .maxCount=2, .maxFileSize=1024*1024*128, .maxWholeUploadSize=1024*1024*255}
        );
        //inbox_3
        auto inbox_3_publicMeta = endpoint::core::Buffer::from("test_inbox_3_publicMeta");
        auto inbox_3_privateMeta = endpoint::core::Buffer::from("test_inbox_3_privateMeta");
        auto inbox_3_id = inboxApi.createInbox(
            context_1_Id,
            users_1_2,
            users_1,
            inbox_3_publicMeta,
            inbox_3_privateMeta,
            std::nullopt
        );
        //message_1
        auto message_1_publicMeta = endpoint::core::Buffer::from("test_message_1_publicMeta");
        auto message_1_privateMeta = endpoint::core::Buffer::from("test_message_1_privateMeta");
        auto message_1_data = endpoint::core::Buffer::from("message_from_sendMessage");
        auto message_1_id = threadApi.sendMessage(
            thread_1_id,
            message_1_publicMeta,
            message_1_privateMeta,
            message_1_data
        );
        //sendMessage
        auto message_2_publicMeta = endpoint::core::Buffer::from("test_message_2_publicMeta");
        auto message_2_privateMeta = endpoint::core::Buffer::from("test_message_2_privateMeta");
        auto message_2_data = endpoint::core::Buffer::from("message_from_sendMessage");
        auto message_2_id = threadApi.sendMessage(
            thread_1_id,
            message_2_publicMeta,
            message_2_privateMeta,
            message_2_data
        );
        //file_1
        std::string file_1_publicMeta = "test_fileData_1_publicMeta";
        std::string file_1_privateMeta = "test_fileData_1_privateMeta";
        std::string file_1_data = "test_fileData_1";
        auto file_1_handle = storeApi.createFile(store_1_id, endpoint::core::Buffer::from(file_1_publicMeta), endpoint::core::Buffer::from(file_1_privateMeta), file_1_data.size());
        storeApi.writeToFile(file_1_handle, endpoint::core::Buffer::from(file_1_data));
        auto file_1_id = storeApi.closeFile(file_1_handle);
        //file_2
        std::string file_2_publicMeta = "test_fileData_2_publicMeta";
        std::string file_2_privateMeta = "test_fileData_2_privateMeta";
        std::string file_2_data = "test_fileData_2_extraText";
        auto file_2_handle = storeApi.createFile(store_1_id, endpoint::core::Buffer::from(file_2_publicMeta), endpoint::core::Buffer::from(file_2_privateMeta), file_2_data.size());
        storeApi.writeToFile(file_2_handle, endpoint::core::Buffer::from(file_2_data));
        auto file_2_id = storeApi.closeFile(file_2_handle);
        //entry_1
        std::string entry_1_file_0_publicMeta = "test_entry_1_FileData_0_publicMeta";
        std::string entry_1_file_1_publicMeta = "test_entry_1_FileData_1_publicMeta";
        std::string entry_1_file_0_privateMeta = "test_entry_1_FileData_0_privateMeta";
        std::string entry_1_file_1_privateMeta = "test_entry_1_FileData_1_privateMeta";
        std::string entry_1_file_0_data = "test_entry_1_FileData_0";
        std::string entry_1_file_1_data = "test_entry_1_FileData_1";
        auto inbox_file_0_handle = inboxApi.createFileHandle(endpoint::core::Buffer::from(entry_1_file_0_publicMeta), endpoint::core::Buffer::from(entry_1_file_0_privateMeta), entry_1_file_0_data.size());
        auto inbox_file_1_handle = inboxApi.createFileHandle(endpoint::core::Buffer::from(entry_1_file_1_publicMeta), endpoint::core::Buffer::from(entry_1_file_1_privateMeta), entry_1_file_1_data.size());
        std::string entry_1_data = "message_from_inboxSendCommit_1";
        auto inbox_1_handle = inboxApi.prepareEntry(inbox_1_id, endpoint::core::Buffer::from(entry_1_data), {inbox_file_0_handle,inbox_file_1_handle}, std::nullopt);
        inboxApi.writeToFile(inbox_1_handle, inbox_file_0_handle, endpoint::core::Buffer::from(entry_1_file_0_data));
        inboxApi.writeToFile(inbox_1_handle, inbox_file_1_handle, endpoint::core::Buffer::from(entry_1_file_1_data));
        inboxApi.sendEntry(inbox_1_handle);
        //entry_2
        std::string entry_2_data = "message_from_inboxSendCommit_2";
        auto inbox_2_handle = inboxApi.prepareEntry(inbox_1_id, endpoint::core::Buffer::from(entry_2_data), {}, std::nullopt);
        inboxApi.sendEntry(inbox_2_handle);


        auto thread_1_server_data = threadApi.getThread(thread_1_id);
        auto store_1_server_data = storeApi.getStore(store_1_id);
        auto thread_2_server_data = threadApi.getThread(thread_2_id);
        auto store_2_server_data = storeApi.getStore(store_2_id);
        auto thread_3_server_data = threadApi.getThread(thread_3_id);
        auto store_3_server_data = storeApi.getStore(store_3_id);
        auto inbox_1_server_data = inboxApi.getInbox(inbox_1_id);
        auto inbox_2_server_data = inboxApi.getInbox(inbox_2_id);
        auto inbox_3_server_data = inboxApi.getInbox(inbox_3_id);

        auto message_1_server_data = threadApi.getMessage(message_1_id);
        auto message_2_server_data = threadApi.getMessage(message_2_id);
        auto file_1_server_metaData = storeApi.getFile(file_1_id);
        auto file_2_server_metaData = storeApi.getFile(file_2_id);
        auto entry_1_server_data = inboxApi.listEntries(inbox_1_id, {.skip=0, .limit=1, .sortOrder="asc"}).readItems[0];
        auto entry_2_server_data = inboxApi.listEntries(inbox_1_id, {.skip=1, .limit=1, .sortOrder="asc"}).readItems[0];

        //writing data to ini file
        fstream iniFileWriter;
        iniFileWriter.open(iniFilePath, ios::app);
        if(iniFileWriter.is_open()) {
            //Thread_1
            iniFileWriter << "[Thread_1]" << std::endl;
            iniFileWriter << "threadId = " << thread_1_server_data.threadId << std::endl;
            iniFileWriter << "contextId = " << thread_1_server_data.contextId << std::endl;
            iniFileWriter << "createDate = " << thread_1_server_data.createDate << std::endl;
            iniFileWriter << "creator = " << thread_1_server_data.creator << std::endl;
            iniFileWriter << "lastModificationDate = " << thread_1_server_data.lastModificationDate << std::endl;
            iniFileWriter << "lastModifier = " << thread_1_server_data.lastModifier << std::endl;
            iniFileWriter << "version = " << thread_1_server_data.version << std::endl;
            iniFileWriter << "lastMsgDate = " << thread_1_server_data.lastMsgDate << std::endl;
            iniFileWriter << "publicMeta_inHex = " << utils::Hex::from(thread_1_server_data.publicMeta.stdString()) << std::endl;
            iniFileWriter << "privateMeta_inHex = " << utils::Hex::from(thread_1_server_data.privateMeta.stdString()) << std::endl;
            iniFileWriter << "messagesCount = " << thread_1_server_data.messagesCount << std::endl;
            iniFileWriter << "statusCode = " << thread_1_server_data.statusCode << std::endl;
            iniFileWriter << "dataStructureVersion = " << thread_1_server_data.dataStructureVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(thread_1_server_data)) << std::endl;
            iniFileWriter << "uploaded_publicMeta_inHex = " << utils::Hex::from(thread_1_publicMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_privateMeta_inHex = " << utils::Hex::from(thread_1_privateMeta.stdString()) << std::endl;
            //Thread_2
            iniFileWriter << "[Thread_2]" << std::endl;
            iniFileWriter << "threadId = " << thread_2_server_data.threadId << std::endl;
            iniFileWriter << "contextId = " << thread_2_server_data.contextId << std::endl;
            iniFileWriter << "createDate = " << thread_2_server_data.createDate << std::endl;
            iniFileWriter << "creator = " << thread_2_server_data.creator << std::endl;
            iniFileWriter << "lastModificationDate = " << thread_2_server_data.lastModificationDate << std::endl;
            iniFileWriter << "lastModifier = " << thread_2_server_data.lastModifier << std::endl;
            iniFileWriter << "version = " << thread_2_server_data.version << std::endl;
            iniFileWriter << "lastMsgDate = " << thread_2_server_data.lastMsgDate << std::endl;
            iniFileWriter << "publicMeta_inHex = " << utils::Hex::from(thread_2_server_data.publicMeta.stdString()) << std::endl;
            iniFileWriter << "privateMeta_inHex = " << utils::Hex::from(thread_2_server_data.privateMeta.stdString()) << std::endl;
            iniFileWriter << "messagesCount = " << thread_2_server_data.messagesCount << std::endl;
            iniFileWriter << "statusCode = " << thread_2_server_data.statusCode << std::endl;
            iniFileWriter << "dataStructureVersion = " << thread_2_server_data.dataStructureVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(thread_2_server_data)) << std::endl;
            iniFileWriter << "uploaded_publicMeta_inHex = " << utils::Hex::from(thread_2_publicMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_privateMeta_inHex = " << utils::Hex::from(thread_2_privateMeta.stdString()) << std::endl;
            //Thread_3
            iniFileWriter << "[Thread_3]" << std::endl;
            iniFileWriter << "threadId = " << thread_3_server_data.threadId << std::endl;
            iniFileWriter << "contextId = " << thread_3_server_data.contextId << std::endl;
            iniFileWriter << "createDate = " << thread_3_server_data.createDate << std::endl;
            iniFileWriter << "creator = " << thread_3_server_data.creator << std::endl;
            iniFileWriter << "lastModificationDate = " << thread_3_server_data.lastModificationDate << std::endl;
            iniFileWriter << "lastModifier = " << thread_3_server_data.lastModifier << std::endl;
            iniFileWriter << "version = " << thread_3_server_data.version << std::endl;
            iniFileWriter << "lastMsgDate = " << thread_3_server_data.lastMsgDate << std::endl;
            iniFileWriter << "publicMeta_inHex = " << utils::Hex::from(thread_3_server_data.publicMeta.stdString()) << std::endl;
            iniFileWriter << "privateMeta_inHex = " << utils::Hex::from(thread_3_server_data.privateMeta.stdString()) << std::endl;
            iniFileWriter << "messagesCount = " << thread_3_server_data.messagesCount << std::endl;
            iniFileWriter << "statusCode = " << thread_3_server_data.statusCode << std::endl;
            iniFileWriter << "dataStructureVersion = " << thread_3_server_data.dataStructureVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(thread_3_server_data)) << std::endl;
            iniFileWriter << "uploaded_publicMeta_inHex = " << utils::Hex::from(thread_3_publicMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_privateMeta_inHex = " << utils::Hex::from(thread_3_privateMeta.stdString()) << std::endl;
            //Store_1
            iniFileWriter << "[Store_1]" << std::endl;
            iniFileWriter << "storeId = " << store_1_server_data.storeId << std::endl;
            iniFileWriter << "contextId = " << store_1_server_data.contextId << std::endl;
            iniFileWriter << "createDate = " << store_1_server_data.createDate << std::endl;
            iniFileWriter << "creator = " << store_1_server_data.creator << std::endl;
            iniFileWriter << "lastModificationDate = " << store_1_server_data.lastModificationDate << std::endl;
            iniFileWriter << "lastFileDate = " << store_1_server_data.lastFileDate << std::endl;
            iniFileWriter << "lastModifier = " << store_1_server_data.lastModifier << std::endl;
            iniFileWriter << "version = " << store_1_server_data.version << std::endl;
            iniFileWriter << "publicMeta_inHex = " << utils::Hex::from(store_1_server_data.publicMeta.stdString()) << std::endl;
            iniFileWriter << "privateMeta_inHex = " << utils::Hex::from(store_1_server_data.privateMeta.stdString()) << std::endl;
            iniFileWriter << "filesCount = " << store_1_server_data.filesCount << std::endl;
            iniFileWriter << "statusCode = " << store_1_server_data.statusCode << std::endl;
            iniFileWriter << "dataStructureVersion = " << store_1_server_data.dataStructureVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(store_1_server_data)) << std::endl;
            iniFileWriter << "uploaded_publicMeta_inHex = " << utils::Hex::from(store_1_publicMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_privateMeta_inHex = " << utils::Hex::from(store_1_privateMeta.stdString()) << std::endl;
            //Store_2
            iniFileWriter << "[Store_2]" << std::endl;
            iniFileWriter << "storeId = " << store_2_server_data.storeId << std::endl;
            iniFileWriter << "contextId = " << store_2_server_data.contextId << std::endl;
            iniFileWriter << "createDate = " << store_2_server_data.createDate << std::endl;
            iniFileWriter << "creator = " << store_2_server_data.creator << std::endl;
            iniFileWriter << "lastModificationDate = " << store_2_server_data.lastModificationDate << std::endl;
            iniFileWriter << "lastFileDate = " << store_2_server_data.lastFileDate << std::endl;
            iniFileWriter << "lastModifier = " << store_2_server_data.lastModifier << std::endl;
            iniFileWriter << "version = " << store_2_server_data.version << std::endl;
            iniFileWriter << "publicMeta_inHex = " << utils::Hex::from(store_2_server_data.publicMeta.stdString()) << std::endl;
            iniFileWriter << "privateMeta_inHex = " << utils::Hex::from(store_2_server_data.privateMeta.stdString()) << std::endl;
            iniFileWriter << "filesCount = " << store_2_server_data.filesCount << std::endl;
            iniFileWriter << "statusCode = " << store_2_server_data.statusCode << std::endl;
            iniFileWriter << "dataStructureVersion = " << store_2_server_data.dataStructureVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(store_2_server_data)) << std::endl;
            iniFileWriter << "uploaded_publicMeta_inHex = " << utils::Hex::from(store_2_publicMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_privateMeta_inHex = " << utils::Hex::from(store_2_privateMeta.stdString()) << std::endl;
            //Store_3
            iniFileWriter << "[Store_3]" << std::endl;
            iniFileWriter << "storeId = " << store_3_server_data.storeId << std::endl;
            iniFileWriter << "contextId = " << store_3_server_data.contextId << std::endl;
            iniFileWriter << "createDate = " << store_3_server_data.createDate << std::endl;
            iniFileWriter << "creator = " << store_3_server_data.creator << std::endl;
            iniFileWriter << "lastModificationDate = " << store_3_server_data.lastModificationDate << std::endl;
            iniFileWriter << "lastFileDate = " << store_3_server_data.lastFileDate << std::endl;
            iniFileWriter << "lastModifier = " << store_3_server_data.lastModifier << std::endl;
            iniFileWriter << "version = " << store_3_server_data.version << std::endl;
            iniFileWriter << "publicMeta_inHex = " << utils::Hex::from(store_3_server_data.publicMeta.stdString()) << std::endl;
            iniFileWriter << "privateMeta_inHex = " << utils::Hex::from(store_3_server_data.privateMeta.stdString()) << std::endl;
            iniFileWriter << "filesCount = " << store_3_server_data.filesCount << std::endl;
            iniFileWriter << "statusCode = " << store_3_server_data.statusCode << std::endl;
            iniFileWriter << "dataStructureVersion = " << store_3_server_data.dataStructureVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(store_3_server_data)) << std::endl;
            iniFileWriter << "uploaded_publicMeta_inHex = " << utils::Hex::from(store_3_publicMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_privateMeta_inHex = " << utils::Hex::from(store_3_privateMeta.stdString()) << std::endl;
            //Inbox_1
            iniFileWriter << "[Inbox_1]" << std::endl;
            iniFileWriter << "inboxId = " << inbox_1_server_data.inboxId << std::endl;
            iniFileWriter << "contextId = " << inbox_1_server_data.contextId << std::endl;
            iniFileWriter << "createDate = " << inbox_1_server_data.createDate << std::endl;
            iniFileWriter << "creator = " << inbox_1_server_data.creator << std::endl;
            iniFileWriter << "lastModificationDate = " << inbox_1_server_data.lastModificationDate << std::endl;
            iniFileWriter << "lastModifier = " << inbox_1_server_data.lastModifier << std::endl;
            iniFileWriter << "version = " << inbox_1_server_data.version << std::endl;
            iniFileWriter << "publicMeta_inHex = " << utils::Hex::from(inbox_1_server_data.publicMeta.stdString()) << std::endl;
            iniFileWriter << "privateMeta_inHex = " << utils::Hex::from(inbox_1_server_data.privateMeta.stdString()) << std::endl;
            iniFileWriter << "statusCode = " << inbox_1_server_data.statusCode << std::endl;
            iniFileWriter << "dataStructureVersion = " << inbox_1_server_data.dataStructureVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(inbox_1_server_data)) << std::endl;
            iniFileWriter << "uploaded_publicMeta_inHex = " << utils::Hex::from(inbox_1_publicMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_privateMeta_inHex = " << utils::Hex::from(inbox_1_privateMeta.stdString()) << std::endl;
            //Inbox_2
            iniFileWriter << "[Inbox_2]" << std::endl;
            iniFileWriter << "inboxId = " << inbox_2_server_data.inboxId << std::endl;
            iniFileWriter << "contextId = " << inbox_2_server_data.contextId << std::endl;
            iniFileWriter << "createDate = " << inbox_2_server_data.createDate << std::endl;
            iniFileWriter << "creator = " << inbox_2_server_data.creator << std::endl;
            iniFileWriter << "lastModificationDate = " << inbox_2_server_data.lastModificationDate << std::endl;
            iniFileWriter << "lastModifier = " << inbox_2_server_data.lastModifier << std::endl;
            iniFileWriter << "version = " << inbox_2_server_data.version << std::endl;
            iniFileWriter << "publicMeta_inHex = " << utils::Hex::from(inbox_2_server_data.publicMeta.stdString()) << std::endl;
            iniFileWriter << "privateMeta_inHex = " << utils::Hex::from(inbox_2_server_data.privateMeta.stdString()) << std::endl;
            iniFileWriter << "filesConfig_minCount = " << inbox_2_server_data.filesConfig.value().minCount << std::endl;
            iniFileWriter << "filesConfig_maxCount = " << inbox_2_server_data.filesConfig.value().maxCount << std::endl;
            iniFileWriter << "filesConfig_maxFileSize = " << inbox_2_server_data.filesConfig.value().maxFileSize << std::endl;
            iniFileWriter << "filesConfig_maxWholeUploadSize = " << inbox_2_server_data.filesConfig.value().maxWholeUploadSize << std::endl;
            iniFileWriter << "statusCode = " << inbox_2_server_data.statusCode << std::endl;
            iniFileWriter << "dataStructureVersion = " << inbox_2_server_data.dataStructureVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(inbox_2_server_data)) << std::endl;
            iniFileWriter << "uploaded_publicMeta_inHex = " << utils::Hex::from(inbox_2_publicMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_privateMeta_inHex = " << utils::Hex::from(inbox_2_privateMeta.stdString()) << std::endl;
            //Inbox_3
            iniFileWriter << "[Inbox_3]" << std::endl;
            iniFileWriter << "inboxId = " << inbox_3_server_data.inboxId << std::endl;
            iniFileWriter << "contextId = " << inbox_3_server_data.contextId << std::endl;
            iniFileWriter << "createDate = " << inbox_3_server_data.createDate << std::endl;
            iniFileWriter << "creator = " << inbox_3_server_data.creator << std::endl;
            iniFileWriter << "lastModificationDate = " << inbox_3_server_data.lastModificationDate << std::endl;
            iniFileWriter << "lastModifier = " << inbox_3_server_data.lastModifier << std::endl;
            iniFileWriter << "version = " << inbox_3_server_data.version << std::endl;
            iniFileWriter << "publicMeta_inHex = " << utils::Hex::from(inbox_3_server_data.publicMeta.stdString()) << std::endl;
            iniFileWriter << "privateMeta_inHex = " << utils::Hex::from(inbox_3_server_data.privateMeta.stdString()) << std::endl;
            iniFileWriter << "statusCode = " << inbox_3_server_data.statusCode << std::endl;
            iniFileWriter << "dataStructureVersion = " << inbox_3_server_data.dataStructureVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(inbox_3_server_data)) << std::endl;
            iniFileWriter << "uploaded_publicMeta_inHex = " << utils::Hex::from(inbox_3_publicMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_privateMeta_inHex = " << utils::Hex::from(inbox_3_privateMeta.stdString()) << std::endl;


            //Message_1
            iniFileWriter << "[Message_1]" << std::endl;
            iniFileWriter << "info_threadId = " << message_1_server_data.info.threadId << std::endl;
            iniFileWriter << "info_messageId = " << message_1_server_data.info.messageId << std::endl;
            iniFileWriter << "info_createDate = " << message_1_server_data.info.createDate << std::endl;
            iniFileWriter << "info_author = " << message_1_server_data.info.author << std::endl;
            iniFileWriter << "publicMeta_inHex = " << utils::Hex::from(message_1_server_data.publicMeta.stdString()) << std::endl;
            iniFileWriter << "privateMeta_inHex = " << utils::Hex::from(message_1_server_data.privateMeta.stdString()) << std::endl;
            iniFileWriter << "data_inHex = " << utils::Hex::from(message_1_server_data.data.stdString()) << std::endl;
            iniFileWriter << "authorPubKey = " << message_1_server_data.authorPubKey << std::endl;
            iniFileWriter << "statusCode = " << message_1_server_data.statusCode << std::endl;
            iniFileWriter << "dataStructureVersion = " << message_1_server_data.dataStructureVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(message_1_server_data)) << std::endl;

            iniFileWriter << "uploaded_publicMeta_inHex = " << utils::Hex::from(message_1_publicMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_privateMeta_inHex = " << utils::Hex::from(message_1_privateMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_data_inHex = " << utils::Hex::from(message_1_data.stdString()) << std::endl;
            //Message_2
            iniFileWriter << "[Message_2]" << std::endl;
            iniFileWriter << "info_threadId = " << message_2_server_data.info.threadId << std::endl;
            iniFileWriter << "info_messageId = " << message_2_server_data.info.messageId << std::endl;
            iniFileWriter << "info_createDate = " << message_2_server_data.info.createDate << std::endl;
            iniFileWriter << "info_author = " << message_2_server_data.info.author << std::endl;
            iniFileWriter << "publicMeta_inHex = " << utils::Hex::from(message_2_server_data.publicMeta.stdString()) << std::endl;
            iniFileWriter << "privateMeta_inHex = " << utils::Hex::from(message_2_server_data.privateMeta.stdString()) << std::endl;
            iniFileWriter << "data_inHex = " << utils::Hex::from(message_2_server_data.data.stdString()) << std::endl;
            iniFileWriter << "authorPubKey = " << message_2_server_data.authorPubKey << std::endl;
            iniFileWriter << "statusCode = " << message_2_server_data.statusCode << std::endl;
            iniFileWriter << "dataStructureVersion = " << message_2_server_data.dataStructureVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(message_2_server_data)) << std::endl;

            iniFileWriter << "uploaded_publicMeta_inHex = " << utils::Hex::from(message_2_publicMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_privateMeta_inHex = " << utils::Hex::from(message_2_privateMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_data_inHex = " << utils::Hex::from(message_2_data.stdString()) << std::endl;
            //File_1
            iniFileWriter << "[File_1]" << std::endl;
            iniFileWriter << "info_storeId = " << file_1_server_metaData.info.storeId << std::endl;
            iniFileWriter << "info_fileId = " << file_1_server_metaData.info.fileId << std::endl;
            iniFileWriter << "info_createDate = " << file_1_server_metaData.info.createDate << std::endl;
            iniFileWriter << "info_author = " << file_1_server_metaData.info.author << std::endl;
            iniFileWriter << "publicMeta_inHex = " << utils::Hex::from(file_1_server_metaData.publicMeta.stdString()) << std::endl;
            iniFileWriter << "privateMeta_inHex = " << utils::Hex::from(file_1_server_metaData.privateMeta.stdString()) << std::endl;
            iniFileWriter << "size = " << file_1_server_metaData.size << std::endl;
            iniFileWriter << "authorPubKey = " << file_1_server_metaData.authorPubKey << std::endl;
            iniFileWriter << "statusCode = " << file_1_server_metaData.statusCode << std::endl;
            iniFileWriter << "dataStructureVersion = " << file_1_server_metaData.dataStructureVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(file_1_server_metaData)) << std::endl;

            iniFileWriter << "uploaded_publicMeta_inHex = " << utils::Hex::from(file_1_publicMeta) << std::endl;
            iniFileWriter << "uploaded_privateMeta_inHex = " << utils::Hex::from(file_1_privateMeta) << std::endl;
            iniFileWriter << "uploaded_size = " << file_1_data.size() << std::endl;
            iniFileWriter << "uploaded_data_inHex = " << utils::Hex::from(file_1_data) << std::endl;
            //File_2
            iniFileWriter << "[File_2]" << std::endl;
            iniFileWriter << "info_storeId = " << file_2_server_metaData.info.storeId << std::endl;
            iniFileWriter << "info_fileId = " << file_2_server_metaData.info.fileId << std::endl;
            iniFileWriter << "info_createDate = " << file_2_server_metaData.info.createDate << std::endl;
            iniFileWriter << "info_author = " << file_2_server_metaData.info.author << std::endl;
            iniFileWriter << "publicMeta_inHex = " << utils::Hex::from(file_2_server_metaData.publicMeta.stdString()) << std::endl;
            iniFileWriter << "privateMeta_inHex = " << utils::Hex::from(file_2_server_metaData.privateMeta.stdString()) << std::endl;
            iniFileWriter << "size = " << file_2_server_metaData.size << std::endl;
            iniFileWriter << "authorPubKey = " << file_2_server_metaData.authorPubKey << std::endl;
            iniFileWriter << "statusCode = " << file_2_server_metaData.statusCode << std::endl;
            iniFileWriter << "dataStructureVersion = " << file_2_server_metaData.dataStructureVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(file_2_server_metaData)) << std::endl;

            iniFileWriter << "uploaded_publicMeta_inHex = " << utils::Hex::from(file_2_publicMeta) << std::endl;
            iniFileWriter << "uploaded_privateMeta_inHex = " << utils::Hex::from(file_2_privateMeta) << std::endl;
            iniFileWriter << "uploaded_size = " << file_2_data.size() << std::endl;
            iniFileWriter << "uploaded_data_inHex = " << utils::Hex::from(file_2_data) << std::endl;
            //Entry_1
            iniFileWriter << "[Entry_1]" << std::endl;
            iniFileWriter << "entryId = " << entry_1_server_data.entryId << std::endl;
            iniFileWriter << "inboxId = " << entry_1_server_data.inboxId << std::endl;
            iniFileWriter << "data_inHex = " << utils::Hex::from(entry_1_server_data.data.stdString()) << std::endl;
            iniFileWriter << "authorPubKey = " << entry_1_server_data.authorPubKey << std::endl;
            iniFileWriter << "createDate = " << entry_1_server_data.createDate << std::endl;
            iniFileWriter << "statusCode = " << entry_1_server_data.statusCode << std::endl;
            iniFileWriter << "dataStructureVersion = " << entry_1_server_data.dataStructureVersion << std::endl;
            iniFileWriter << "file_0_info_storeId = " << entry_1_server_data.files[0].info.storeId << std::endl;
            iniFileWriter << "file_0_info_fileId = " << entry_1_server_data.files[0].info.fileId << std::endl;
            iniFileWriter << "file_0_info_createDate = " << entry_1_server_data.files[0].info.createDate << std::endl;
            iniFileWriter << "file_0_info_author = " << entry_1_server_data.files[0].info.author << std::endl;
            iniFileWriter << "file_0_authorPubKey = " << entry_1_server_data.files[0].authorPubKey << std::endl;
            iniFileWriter << "file_0_statusCode = " << entry_1_server_data.files[0].statusCode << std::endl;
            iniFileWriter << "file_0_dataStructureVersion = " << entry_1_server_data.files[0].dataStructureVersion << std::endl;
            iniFileWriter << "file_0_publicMeta_inHex = " << utils::Hex::from(entry_1_server_data.files[0].publicMeta.stdString()) << std::endl;
            iniFileWriter << "file_0_privateMeta_inHex = " << utils::Hex::from(entry_1_server_data.files[0].privateMeta.stdString()) << std::endl;
            iniFileWriter << "file_0_size = " << entry_1_server_data.files[0].size << std::endl;

            iniFileWriter << "file_1_info_storeId = " << entry_1_server_data.files[1].info.storeId << std::endl;
            iniFileWriter << "file_1_info_fileId = " << entry_1_server_data.files[1].info.fileId << std::endl;
            iniFileWriter << "file_1_info_createDate = " << entry_1_server_data.files[1].info.createDate << std::endl;
            iniFileWriter << "file_1_info_author = " << entry_1_server_data.files[1].info.author << std::endl;
            iniFileWriter << "file_1_authorPubKey = " << entry_1_server_data.files[1].authorPubKey << std::endl;
            iniFileWriter << "file_1_statusCode = " << entry_1_server_data.files[1].statusCode << std::endl;
            iniFileWriter << "file_0_dataStructureVersion = " << entry_1_server_data.files[1].dataStructureVersion << std::endl;
            iniFileWriter << "file_1_publicMeta_inHex = " << utils::Hex::from(entry_1_server_data.files[1].publicMeta.stdString()) << std::endl;
            iniFileWriter << "file_1_privateMeta_inHex = " << utils::Hex::from(entry_1_server_data.files[1].privateMeta.stdString()) << std::endl;
            iniFileWriter << "file_1_size = " << entry_1_server_data.files[1].size << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(entry_1_server_data)) << std::endl;

            iniFileWriter << "uploaded_file_0_publicMeta_inHex = " << utils::Hex::from(entry_1_file_0_publicMeta) << std::endl;
            iniFileWriter << "uploaded_file_0_privateMeta_inHex = " << utils::Hex::from(entry_1_file_0_privateMeta) << std::endl;
            iniFileWriter << "uploaded_file_0_size = " << entry_1_file_0_data.size() << std::endl;
            iniFileWriter << "uploaded_file_0_data_inHex = " << utils::Hex::from(entry_1_file_0_data) << std::endl;
            iniFileWriter << "uploaded_file_1_publicMeta_inHex = " << utils::Hex::from(entry_1_file_1_publicMeta) << std::endl;
            iniFileWriter << "uploaded_file_1_privateMeta_inHex = " << utils::Hex::from(entry_1_file_1_privateMeta) << std::endl;
            iniFileWriter << "uploaded_file_1_size = " << entry_1_file_1_data.size() << std::endl;
            iniFileWriter << "uploaded_file_1_data_inHex = " << utils::Hex::from(entry_1_file_1_data) << std::endl;
            iniFileWriter << "uploaded_data_inHex = " << utils::Hex::from(entry_1_data) << std::endl;
            //Entry_2
            iniFileWriter << "[Entry_2]" << std::endl;
            iniFileWriter << "entryId = " << entry_2_server_data.entryId << std::endl;
            iniFileWriter << "inboxId = " << entry_2_server_data.inboxId << std::endl;
            iniFileWriter << "data_inHex = " << utils::Hex::from(entry_2_server_data.data.stdString()) << std::endl;
            iniFileWriter << "authorPubKey = " << entry_2_server_data.authorPubKey << std::endl;
            iniFileWriter << "createDate = " << entry_2_server_data.createDate << std::endl;
            iniFileWriter << "statusCode = " << entry_2_server_data.statusCode << std::endl;
            iniFileWriter << "dataStructureVersion = " << entry_2_server_data.dataStructureVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(entry_2_server_data)) << std::endl;

            iniFileWriter << "uploaded_data_inHex = " << utils::Hex::from(entry_2_data) << std::endl;
            iniFileWriter.close();
        }
        iniFileWriter.open(iniFileJSONPath, ios::out | ios::trunc);
        if(iniFileWriter.is_open()) {
            Poco::JSON::Object::Ptr data = new Poco::JSON::Object();
            Poco::JSON::Object::Ptr data_login = new Poco::JSON::Object();
            data_login->set("user_1_privKey", user_1_PrivKey);
            data_login->set("user_1_pubKey", user_1_PubKey);
            data_login->set("user_1_id", user_1_Id);
            data_login->set("user_2_privKey", user_2_PrivKey);
            data_login->set("user_2_pubKey", user_2_PubKey);
            data_login->set("user_2_id", user_2_Id);
            data_login->set("solutionId", solution);
            data_login->set("instanceUrl", platformUrl);
            data->set("Login", data_login);
            Poco::JSON::Object::Ptr data_context_1 = new Poco::JSON::Object();
            data_context_1->set("contextId", context_1_Id);
            data->set("Context_1", data_context_1);
            Poco::JSON::Object::Ptr data_context_2 = new Poco::JSON::Object();
            data_context_2->set("contextId", context_2_Id);
            data->set("Context_2", data_context_2);

            Poco::JSON::Object::Ptr data_thread_1 = new Poco::JSON::Object();
            data_thread_1->set("server_data", (_serializer.serialize(thread_1_server_data)));
            data_thread_1->set("uploaded_publicMeta_inBase64", utils::Base64::from(thread_1_publicMeta.stdString()));
            data_thread_1->set("uploaded_privateMeta_inBase64", utils::Base64::from(thread_1_privateMeta.stdString()));
            data->set("Thread_1", data_thread_1);
            Poco::JSON::Object::Ptr data_thread_2 = new Poco::JSON::Object();
            data_thread_2->set("server_data", (_serializer.serialize(thread_2_server_data)));
            data_thread_2->set("uploaded_publicMeta_inBase64", utils::Base64::from(thread_2_publicMeta.stdString()));
            data_thread_2->set("uploaded_privateMeta_inBase64", utils::Base64::from(thread_2_privateMeta.stdString()));
            data->set("Thread_2", data_thread_2);
            Poco::JSON::Object::Ptr data_thread_3 = new Poco::JSON::Object();
            data_thread_3->set("server_data", (_serializer.serialize(thread_3_server_data)));
            data_thread_3->set("uploaded_publicMeta_inBase64", utils::Base64::from(thread_3_publicMeta.stdString()));
            data_thread_3->set("uploaded_privateMeta_inBase64", utils::Base64::from(thread_3_privateMeta.stdString()));
            data->set("Thread_3", data_thread_3);

            Poco::JSON::Object::Ptr data_store_1 = new Poco::JSON::Object();
            data_store_1->set("server_data", (_serializer.serialize(store_1_server_data)));
            data_store_1->set("uploaded_publicMeta_inBase64", utils::Base64::from(store_1_publicMeta.stdString()));
            data_store_1->set("uploaded_privateMeta_inBase64", utils::Base64::from(store_1_privateMeta.stdString()));
            data->set("Store_1", data_store_1);
            Poco::JSON::Object::Ptr data_store_2 = new Poco::JSON::Object();
            data_store_2->set("server_data", (_serializer.serialize(store_2_server_data)));
            data_store_2->set("uploaded_publicMeta_inBase64", utils::Base64::from(store_2_publicMeta.stdString()));
            data_store_2->set("uploaded_privateMeta_inBase64", utils::Base64::from(store_2_privateMeta.stdString()));
            data->set("Store_2", data_store_2);
            Poco::JSON::Object::Ptr data_store_3 = new Poco::JSON::Object();
            data_store_3->set("server_data", (_serializer.serialize(store_3_server_data)));
            data_store_3->set("uploaded_publicMeta_inBase64", utils::Base64::from(store_3_publicMeta.stdString()));
            data_store_3->set("uploaded_privateMeta_inBase64", utils::Base64::from(store_3_privateMeta.stdString()));
            data->set("Store_3", data_store_3);
            Poco::JSON::Object::Ptr data_inbox_1 = new Poco::JSON::Object();
            data_inbox_1->set("server_data", (_serializer.serialize(inbox_1_server_data)));
            data_inbox_1->set("uploaded_publicMeta_inBase64", utils::Base64::from(inbox_1_publicMeta.stdString()));
            data_inbox_1->set("uploaded_privateMeta_inBase64", utils::Base64::from(inbox_1_privateMeta.stdString()));
            data->set("Inbox_1", data_inbox_1);
            Poco::JSON::Object::Ptr data_inbox_2 = new Poco::JSON::Object();
            data_inbox_2->set("server_data", (_serializer.serialize(inbox_2_server_data)));
            data_inbox_2->set("uploaded_publicMeta_inBase64", utils::Base64::from(inbox_2_publicMeta.stdString()));
            data_inbox_2->set("uploaded_privateMeta_inBase64", utils::Base64::from(inbox_2_privateMeta.stdString()));
            data->set("Inbox_2", data_inbox_2);
            Poco::JSON::Object::Ptr data_inbox_3 = new Poco::JSON::Object();
            data_inbox_3->set("server_data", (_serializer.serialize(inbox_3_server_data)));
            data_inbox_3->set("uploaded_publicMeta_inBase64", utils::Base64::from(inbox_3_publicMeta.stdString()));
            data_inbox_3->set("uploaded_privateMeta_inBase64", utils::Base64::from(inbox_3_privateMeta.stdString()));
            data->set("Inbox_3", data_inbox_3);


            Poco::JSON::Object::Ptr data_message_1 = new Poco::JSON::Object();
            data_message_1->set("server_data", (_serializer.serialize(message_1_server_data)));
            data_message_1->set("uploaded_publicMeta_inBase64", utils::Base64::from(message_1_publicMeta.stdString()));
            data_message_1->set("uploaded_privateMeta_inBase64", utils::Base64::from(message_1_privateMeta.stdString()));
            data_message_1->set("uploaded_data_inBase64", utils::Base64::from(message_1_data.stdString()));
            data->set("Message_1", data_message_1);
            Poco::JSON::Object::Ptr data_message_2 = new Poco::JSON::Object();
            data_message_2->set("server_data", (_serializer.serialize(message_2_server_data)));
            data_message_2->set("uploaded_publicMeta_inBase64", utils::Base64::from(message_2_publicMeta.stdString()));
            data_message_2->set("uploaded_privateMeta_inBase64", utils::Base64::from(message_2_privateMeta.stdString()));
            data_message_2->set("uploaded_data_inBase64", utils::Base64::from(message_2_data.stdString()));
            data->set("Message_2", data_message_2);

            Poco::JSON::Object::Ptr data_file_1 = new Poco::JSON::Object();
            data_file_1->set("server_data", (_serializer.serialize(file_1_server_metaData)));
            data_file_1->set("uploaded_publicMeta_inBase64", utils::Base64::from(file_1_publicMeta));
            data_file_1->set("uploaded_privateMeta_inBase64", utils::Base64::from(file_1_privateMeta));
            data_file_1->set("uploaded_size", file_1_data.size());
            data_file_1->set("uploaded_data_inBase64", utils::Base64::from(file_1_data));
            data->set("File_1", data_file_1);
            Poco::JSON::Object::Ptr data_file_2 = new Poco::JSON::Object();
            data_file_2->set("server_data", (_serializer.serialize(file_2_server_metaData)));
            data_file_2->set("uploaded_publicMeta_inBase64", utils::Base64::from(file_2_publicMeta));
            data_file_2->set("uploaded_privateMeta_inBase64", utils::Base64::from(file_2_privateMeta));
            data_file_2->set("uploaded_size", file_2_data.size());
            data_file_2->set("uploaded_data_inBase64", utils::Base64::from(file_2_data));
            data->set("File_2", data_file_2);

            Poco::JSON::Object::Ptr data_entry_1 = new Poco::JSON::Object();
            data_entry_1->set("server_data", (_serializer.serialize(entry_1_server_data)));
            data_entry_1->set("uploaded_file_0_publicMeta_inBase64", utils::Base64::from(entry_1_file_0_publicMeta));
            data_entry_1->set("uploaded_file_0_privateMeta_inBase64", utils::Base64::from(entry_1_file_0_privateMeta));
            data_entry_1->set("uploaded_file_0_size", entry_1_file_0_data.size());
            data_entry_1->set("uploaded_file_0_data_inBase64", utils::Base64::from(entry_1_file_0_data));
            data_entry_1->set("uploaded_file_1_publicMeta_inBase64", utils::Base64::from(entry_1_file_1_publicMeta));
            data_entry_1->set("uploaded_file_1_privateMeta_inBase64", utils::Base64::from(entry_1_file_1_privateMeta));
            data_entry_1->set("uploaded_file_1_size", entry_1_file_1_data.size());
            data_entry_1->set("uploaded_file_1_data_inBase64", utils::Base64::from(entry_1_file_1_data));
            data_entry_1->set("uploaded_data_inBase64", utils::Base64::from(entry_1_data));
            data->set("Entry_1", data_entry_1);
            Poco::JSON::Object::Ptr data_entry_2 = new Poco::JSON::Object();
            data_entry_2->set("server_data", (_serializer.serialize(entry_2_server_data)));
            data_entry_2->set("uploaded_data_inBase64", utils::Base64::from(entry_2_data));
            data->set("Entry_2", data_entry_2);


            iniFileWriter << utils::Utils::stringify(data, true) << std::endl;
            iniFileWriter.close();
        }

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