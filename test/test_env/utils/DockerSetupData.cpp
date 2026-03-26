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
#include <privmx/endpoint/event/EventApi.hpp>
#include <privmx/endpoint/search/SearchApi.hpp>
#include <privmx/endpoint/search/Types.hpp>
#include <privmx/endpoint/search/VarSerializer.hpp>
#include <privmx/endpoint/sql/SqlApi.hpp>
#include <privmx/endpoint/sql/Types.hpp>
#include <privmx/endpoint/sql/VarSerializer.hpp>

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
    char * envVal = getenv("DOCKER_BRIDGE_PORT");
    std::string dockerPort = "";
    if (envVal != NULL) {
        dockerPort = std::string(envVal);
    } else {
        std::cout << "system variable DOCKER_BRIDGE_PORT not set" << std::endl;
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
        endpoint::kvdb::KvdbApi kvdbApi = endpoint::kvdb::KvdbApi::create(connection);
        event::EventApi eventApi = event::EventApi::create(connection);
        endpoint::search::SearchApi searchApi = endpoint::search::SearchApi::create(connection, storeApi, kvdbApi);
        endpoint::sql::SqlApi sqlApi = endpoint::sql::SqlApi::create(connection, storeApi, kvdbApi);
        const std::vector<endpoint::core::UserWithPubKey> users_1 = {
            endpoint::core::UserWithPubKey{.userId=user_1_Id, .pubKey=user_1_PubKey}
        };
        const std::vector<endpoint::core::UserWithPubKey> users_1_2 = {
            endpoint::core::UserWithPubKey{.userId=user_1_Id, .pubKey=user_1_PubKey},
            endpoint::core::UserWithPubKey{.userId=user_2_Id, .pubKey=user_2_PubKey}
        };

        LOG_INFO("Thread 1 - create")
        auto thread_1_publicMeta = endpoint::core::Buffer::from("test_thread_1_publicMeta");
        auto thread_1_privateMeta = endpoint::core::Buffer::from("test_thread_1_privateMeta");
        auto thread_1_id = threadApi.createThread(
            context_1_Id,
            users_1,
            users_1,
            thread_1_publicMeta,
            thread_1_privateMeta
        );
        LOG_INFO("Thread 2 - create")
        auto thread_2_publicMeta = endpoint::core::Buffer::from("test_thread_2_publicMeta");
        auto thread_2_privateMeta = endpoint::core::Buffer::from("test_thread_2_privateMeta");
        auto thread_2_id = threadApi.createThread(
            context_1_Id,
            users_1_2,
            users_1_2,
            thread_2_publicMeta,
            thread_2_privateMeta
        );
        LOG_INFO("Thread 3 - create")
        auto thread_3_publicMeta = endpoint::core::Buffer::from("test_thread_3_publicMeta");
        auto thread_3_privateMeta = endpoint::core::Buffer::from("test_thread_3_privateMeta");
        auto thread_3_id = threadApi.createThread(
            context_1_Id,
            users_1_2,
            users_1,
            thread_3_publicMeta,
            thread_3_privateMeta
        );
        LOG_INFO("Store 1 - create")
        auto store_1_publicMeta = endpoint::core::Buffer::from("test_store_1_publicMeta");
        auto store_1_privateMeta = endpoint::core::Buffer::from("test_store_1_privateMeta");
        auto store_1_id = storeApi.createStore(
            context_1_Id,
            users_1,
            users_1,
            store_1_publicMeta,
            store_1_privateMeta
        );
        LOG_INFO("Store 2 - create")
        auto store_2_publicMeta = endpoint::core::Buffer::from("test_store_2_publicMeta");
        auto store_2_privateMeta = endpoint::core::Buffer::from("test_store_2_privateMeta");
        auto store_2_id = storeApi.createStore(
            context_1_Id,
            users_1_2,
            users_1_2,
            store_2_publicMeta,
            store_2_privateMeta
        );
        LOG_INFO("Store 3 - create")
        auto store_3_publicMeta = endpoint::core::Buffer::from("test_store_3_publicMeta");
        auto store_3_privateMeta = endpoint::core::Buffer::from("test_store_3_privateMeta");
        auto store_3_id = storeApi.createStore(
            context_1_Id,
            users_1_2,
            users_1,
            store_3_publicMeta,
            store_3_privateMeta
        );
        LOG_INFO("Inbox 1 - create")
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
        LOG_INFO("Inbox 2 - create")
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
        LOG_INFO("Inbox 3 - create")
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
        LOG_INFO("Kvdb 1 - create")
        auto kvdb_1_publicMeta = endpoint::core::Buffer::from("test_kvdb_1_publicMeta");
        auto kvdb_1_privateMeta = endpoint::core::Buffer::from("test_kvdb_1_privateMeta");
        auto kvdb_1_id = kvdbApi.createKvdb(
            context_1_Id,
            users_1,
            users_1,
            kvdb_1_publicMeta,
            kvdb_1_privateMeta
        );
        LOG_INFO("Kvdb 2 - create")
        auto kvdb_2_publicMeta = endpoint::core::Buffer::from("test_kvdb_2_publicMeta");
        auto kvdb_2_privateMeta = endpoint::core::Buffer::from("test_kvdb_2_privateMeta");
        auto kvdb_2_id = kvdbApi.createKvdb(
            context_1_Id,
            users_1_2,
            users_1_2,
            kvdb_2_publicMeta,
            kvdb_2_privateMeta
        );
        LOG_INFO("Kvdb 3 - create")
        auto kvdb_3_publicMeta = endpoint::core::Buffer::from("test_kvdb_3_publicMeta");
        auto kvdb_3_privateMeta = endpoint::core::Buffer::from("test_kvdb_3_privateMeta");
        auto kvdb_3_id = kvdbApi.createKvdb(
            context_1_Id,
            users_1_2,
            users_1,
            kvdb_3_publicMeta,
            kvdb_3_privateMeta
        );
        LOG_INFO("SearchIndex 1 - create")
        auto searchIndex_1_publicMeta = endpoint::core::Buffer::from("test_search_index_1_publicMeta");
        auto searchIndex_1_privateMeta = endpoint::core::Buffer::from("test_search_index_1_privateMeta");
        auto searchIndex_1_Id = searchApi.createSearchIndex(
            context_1_Id,
            users_1,
            users_1,
            searchIndex_1_publicMeta,
            searchIndex_1_privateMeta,
            endpoint::search::IndexMode::WITH_CONTENT
        );
        LOG_INFO("SearchIndex 1 - adding documents")
        int64_t indexHandle_1 = searchApi.openSearchIndex(searchIndex_1_Id);
        auto searchIndex_1_doc_1_name = "doc-1";
        auto searchIndex_1_doc_1_content = "Ala ma kota";
        auto searchIndex_1_doc_1_id = searchApi.addDocument(indexHandle_1, searchIndex_1_doc_1_name, searchIndex_1_doc_1_content);
        auto searchIndex_1_doc_2_name = "doc-2";
        auto searchIndex_1_doc_2_content = "Ola ma kota";
        auto searchIndex_1_doc_2_id = searchApi.addDocument(indexHandle_1, searchIndex_1_doc_2_name, searchIndex_1_doc_2_content);
        auto searchIndex_1_docs_common_content_part = "ma kota";
        searchApi.closeSearchIndex(indexHandle_1);

        LOG_INFO("SearchIndex 2 - create")
        auto searchIndex_2_publicMeta = endpoint::core::Buffer::from("test_search_index_2_publicMeta");
        auto searchIndex_2_privateMeta = endpoint::core::Buffer::from("test_search_index_2_privateMeta");
        auto searchIndex_2_Id = searchApi.createSearchIndex(
            context_1_Id,
            users_1_2,
            users_1_2,
            searchIndex_2_publicMeta,
            searchIndex_2_privateMeta,
            endpoint::search::IndexMode::WITHOUT_CONTENT
        );

        LOG_INFO("SearchIndex 3 - create")
        auto searchIndex_3_publicMeta = endpoint::core::Buffer::from("test_search_index_3_publicMeta");
        auto searchIndex_3_privateMeta = endpoint::core::Buffer::from("test_search_index_3_privateMeta");
        auto searchIndex_3_Id = searchApi.createSearchIndex(
            context_1_Id,
            users_1_2,
            users_1,
            searchIndex_3_publicMeta,
            searchIndex_3_privateMeta,
            endpoint::search::IndexMode::WITH_CONTENT
        );

        LOG_INFO("SqlDatabase 1 - create")
        auto sqlDatabase_1_publicMeta = endpoint::core::Buffer::from("test_sql_database_1_publicMeta");
        auto sqlDatabase_1_privateMeta = endpoint::core::Buffer::from("test_sql_database_1_privateMeta");
        auto sqlDatabase_1_Id = sqlApi.createSqlDatabase(
            context_1_Id,
            users_1,
            users_1,
            sqlDatabase_1_publicMeta,
            sqlDatabase_1_privateMeta
        );
        LOG_INFO("SqlDatabase 1 - Adding Data")
        auto databaseHandle_1 = sqlApi.openSqlDatabase(sqlDatabase_1_Id);
        auto sqlDatabase_1_table_1_name = "testing_table";
        auto sqlDatabase_1_table_1_field_1 = "id";
        auto sqlDatabase_1_table_1_field_1_type = sql::DataType::T_INTEGER;
        auto sqlDatabase_1_table_1_field_2 = "text_no_null";
        auto sqlDatabase_1_table_1_field_2_type = sql::DataType::T_TEXT;
        auto sqlDatabase_1_table_1_field_3 = "int";
        auto sqlDatabase_1_table_1_field_3_type = sql::DataType::T_INTEGER;
        auto queryResult_1 = databaseHandle_1->query("CREATE TABLE testing_table (id INTEGER PRIMARY KEY AUTOINCREMENT, text_no_null TEXT NOT NULL UNIQUE, int INTEGER);");
        auto queryResult_1_step = queryResult_1->step();
        
        if(queryResult_1_step->getStatus().code != sql::EvaluationStatusCode::T_DONE) {
            LOG_FATAL("queryResult_1_step->getStatus() code: ", queryResult_1_step->getStatus().code, " | description: ", queryResult_1_step->getStatus().description)
            return -1;
        }
        queryResult_1->finalize();
        auto sqlDatabase_1_table_1_entry_1_field_1 = 1;
        auto sqlDatabase_1_table_1_entry_1_field_2 = "text_value";
        auto sqlDatabase_1_table_1_entry_1_field_3 = 65456;
        auto queryResult_2 = databaseHandle_1->query("INSERT INTO testing_table(text_no_null, int) VALUES ('database_value', 65456);");
        auto queryResult_2_step = queryResult_2->step();
        if(queryResult_2_step->getStatus().code != sql::EvaluationStatusCode::T_DONE) {
            LOG_FATAL("queryResult_2_step->getStatus() code: ", queryResult_2_step->getStatus().code, " | description: ", queryResult_2_step->getStatus().description)
            return -1;
        }
        queryResult_2->finalize();
        auto sqlDatabase_1_table_1_entry_2_field_1 = 2;
        auto sqlDatabase_1_table_1_entry_2_field_2 = "random_text_value";
        auto sqlDatabase_1_table_1_entry_2_field_3 = 0;
        auto queryResult_3 = databaseHandle_1->query("INSERT INTO testing_table(text_no_null, int) VALUES ('random_text_value', 0);");
        auto queryResult_3_step = queryResult_3->step();
        if(queryResult_3_step->getStatus().code != sql::EvaluationStatusCode::T_DONE) {
            LOG_FATAL("queryResult_3_step->getStatus() code: ", queryResult_3_step->getStatus().code, " | description: ", queryResult_3_step->getStatus().description)
            return -1;
        }
        queryResult_3->finalize();


        LOG_INFO("SqlDatabase 2 - create")
        auto sqlDatabase_2_publicMeta = endpoint::core::Buffer::from("test_sql_database_2_publicMeta");
        auto sqlDatabase_2_privateMeta = endpoint::core::Buffer::from("test_sql_database_2_privateMeta");
        auto sqlDatabase_2_Id = sqlApi.createSqlDatabase(
            context_1_Id,
            users_1_2,
            users_1_2,
            sqlDatabase_2_publicMeta,
            sqlDatabase_2_privateMeta
        );
        LOG_INFO("SqlDatabase 3 - create")
        auto sqlDatabase_3_publicMeta = endpoint::core::Buffer::from("test_sql_database_3_publicMeta");
        auto sqlDatabase_3_privateMeta = endpoint::core::Buffer::from("test_sql_database_3_privateMeta");
        auto sqlDatabase_3_Id = sqlApi.createSqlDatabase(
            context_1_Id,
            users_1_2,
            users_1,
            sqlDatabase_3_publicMeta,
            sqlDatabase_3_privateMeta
        );
        
        LOG_INFO("Message 1 - create")
        auto message_1_publicMeta = endpoint::core::Buffer::from("test_message_1_publicMeta");
        auto message_1_privateMeta = endpoint::core::Buffer::from("test_message_1_privateMeta");
        auto message_1_data = endpoint::core::Buffer::from("message_from_sendMessage");
        auto message_1_id = threadApi.sendMessage(
            thread_1_id,
            message_1_publicMeta,
            message_1_privateMeta,
            message_1_data
        );
        LOG_INFO("Message 2 - create")
        auto message_2_publicMeta = endpoint::core::Buffer::from("test_message_2_publicMeta");
        auto message_2_privateMeta = endpoint::core::Buffer::from("test_message_2_privateMeta");
        auto message_2_data = endpoint::core::Buffer::from("message_from_sendMessage");
        auto message_2_id = threadApi.sendMessage(
            thread_1_id,
            message_2_publicMeta,
            message_2_privateMeta,
            message_2_data
        );
        LOG_INFO("File 1 - create")
        std::string file_1_publicMeta = "test_fileData_1_publicMeta";
        std::string file_1_privateMeta = "test_fileData_1_privateMeta";
        std::string file_1_data = "test_fileData_1";
        auto file_1_handle = storeApi.createFile(store_1_id, endpoint::core::Buffer::from(file_1_publicMeta), endpoint::core::Buffer::from(file_1_privateMeta), file_1_data.size());
        storeApi.writeToFile(file_1_handle, endpoint::core::Buffer::from(file_1_data));
        auto file_1_id = storeApi.closeFile(file_1_handle);
        
        LOG_INFO("File 2 - create")
        std::string file_2_publicMeta = "test_fileData_2_publicMeta";
        std::string file_2_privateMeta = "test_fileData_2_privateMeta";
        std::string file_2_data = "test_fileData_2_extraText";
        auto file_2_handle = storeApi.createFile(store_1_id, endpoint::core::Buffer::from(file_2_publicMeta), endpoint::core::Buffer::from(file_2_privateMeta), file_2_data.size());
        storeApi.writeToFile(file_2_handle, endpoint::core::Buffer::from(file_2_data));
        auto file_2_id = storeApi.closeFile(file_2_handle);
        
        LOG_INFO("Inbox Entry 1 - create")
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
        LOG_INFO("Inbox Entry 2 - create")
        std::string entry_2_data = "message_from_inboxSendCommit_2";
        auto inbox_2_handle = inboxApi.prepareEntry(inbox_1_id, endpoint::core::Buffer::from(entry_2_data), {}, std::nullopt);
        inboxApi.sendEntry(inbox_2_handle);
        LOG_INFO("Kvdb Entry 1 - create")
        auto kvdb_entry_1_publicMeta = endpoint::core::Buffer::from("test_kvdb_entry_1_publicMeta");
        auto kvdb_entry_1_privateMeta = endpoint::core::Buffer::from("test_kvdb_entry_1_privateMeta");
        auto kvdb_entry_1_data = endpoint::core::Buffer::from("kvdb_entry_value_1");
        auto kvdb_entry_1_key = "kvdb_entry_key_1";
        kvdbApi.setEntry(
            kvdb_1_id,
            kvdb_entry_1_key,
            kvdb_entry_1_publicMeta,
            kvdb_entry_1_privateMeta,
            kvdb_entry_1_data,
            0
        );
        LOG_INFO("Kvdb Entry 2 - create")
        auto kvdb_entry_2_publicMeta = endpoint::core::Buffer::from("test_kvdb_entry_2_publicMeta");
        auto kvdb_entry_2_privateMeta = endpoint::core::Buffer::from("test_kvdb_entry_2_privateMeta");
        auto kvdb_entry_2_data = endpoint::core::Buffer::from("kvdb_entry_value_2");
        auto kvdb_entry_2_key = "kvdb_entry_key_2";
        kvdbApi.setEntry(
            kvdb_1_id,
            kvdb_entry_2_key,
            kvdb_entry_2_publicMeta,
            kvdb_entry_2_privateMeta,
            kvdb_entry_2_data,
            0
        );
        LOG_INFO("Threads - server download")
        auto thread_1_server_data = threadApi.getThread(thread_1_id);
        auto thread_2_server_data = threadApi.getThread(thread_2_id);
        auto thread_3_server_data = threadApi.getThread(thread_3_id);
        LOG_INFO("Stores - server download")
        auto store_1_server_data = storeApi.getStore(store_1_id);
        auto store_2_server_data = storeApi.getStore(store_2_id);
        auto store_3_server_data = storeApi.getStore(store_3_id);
        LOG_INFO("Inboxes - server download")
        auto inbox_1_server_data = inboxApi.getInbox(inbox_1_id);
        auto inbox_2_server_data = inboxApi.getInbox(inbox_2_id);
        auto inbox_3_server_data = inboxApi.getInbox(inbox_3_id);
        LOG_INFO("Kvdbs - server download")
        auto kvdb_1_server_data = kvdbApi.getKvdb(kvdb_1_id);
        auto kvdb_2_server_data = kvdbApi.getKvdb(kvdb_2_id);
        auto kvdb_3_server_data = kvdbApi.getKvdb(kvdb_3_id);
        LOG_INFO("SearchIndexes - server download")
        auto searchIndex_1_server_data = searchApi.getSearchIndex(searchIndex_1_Id);
        auto searchIndex_2_server_data = searchApi.getSearchIndex(searchIndex_2_Id);
        auto searchIndex_3_server_data = searchApi.getSearchIndex(searchIndex_3_Id);
        LOG_INFO("SqlIndexes - server download")
        auto sqlDatabase_1_server_data = sqlApi.getSqlDatabase(sqlDatabase_1_Id);
        auto sqlDatabase_2_server_data = sqlApi.getSqlDatabase(sqlDatabase_2_Id);
        auto sqlDatabase_3_server_data = sqlApi.getSqlDatabase(sqlDatabase_3_Id);
        LOG_INFO("Messages - server download")
        auto message_1_server_data = threadApi.getMessage(message_1_id);
        auto message_2_server_data = threadApi.getMessage(message_2_id);
        LOG_INFO("Files - server download")
        auto file_1_server_metaData = storeApi.getFile(file_1_id);
        auto file_2_server_metaData = storeApi.getFile(file_2_id);
        LOG_INFO("InboxEntires - server download")
        auto entry_1_server_data = inboxApi.listEntries(inbox_1_id, {.skip=0, .limit=1, .sortOrder="asc"}).readItems[0];
        auto entry_2_server_data = inboxApi.listEntries(inbox_1_id, {.skip=1, .limit=1, .sortOrder="asc"}).readItems[0];
        LOG_INFO("KvdbEntires - server download")
        auto kvdb_entry_1_server_data = kvdbApi.getEntry(kvdb_1_id, kvdb_entry_1_key);
        auto kvdb_entry_2_server_data = kvdbApi.getEntry(kvdb_1_id, kvdb_entry_2_key);

        LOG_INFO("Writing data to ini file")
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
            iniFileWriter << "schemaVersion = " << thread_1_server_data.schemaVersion << std::endl;
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
            iniFileWriter << "schemaVersion = " << thread_2_server_data.schemaVersion << std::endl;
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
            iniFileWriter << "schemaVersion = " << thread_3_server_data.schemaVersion << std::endl;
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
            iniFileWriter << "schemaVersion = " << store_1_server_data.schemaVersion << std::endl;
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
            iniFileWriter << "schemaVersion = " << store_2_server_data.schemaVersion << std::endl;
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
            iniFileWriter << "schemaVersion = " << store_3_server_data.schemaVersion << std::endl;
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
            iniFileWriter << "schemaVersion = " << inbox_1_server_data.schemaVersion << std::endl;
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
            iniFileWriter << "schemaVersion = " << inbox_2_server_data.schemaVersion << std::endl;
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
            iniFileWriter << "schemaVersion = " << inbox_3_server_data.schemaVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(inbox_3_server_data)) << std::endl;
            iniFileWriter << "uploaded_publicMeta_inHex = " << utils::Hex::from(inbox_3_publicMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_privateMeta_inHex = " << utils::Hex::from(inbox_3_privateMeta.stdString()) << std::endl;

            //Kvdb_1
            iniFileWriter << "[Kvdb_1]" << std::endl;
            iniFileWriter << "kvdbId = " << kvdb_1_server_data.kvdbId << std::endl;
            iniFileWriter << "contextId = " << kvdb_1_server_data.contextId << std::endl;
            iniFileWriter << "createDate = " << kvdb_1_server_data.createDate << std::endl;
            iniFileWriter << "creator = " << kvdb_1_server_data.creator << std::endl;
            iniFileWriter << "lastModificationDate = " << kvdb_1_server_data.lastModificationDate << std::endl;
            iniFileWriter << "lastModifier = " << kvdb_1_server_data.lastModifier << std::endl;
            iniFileWriter << "version = " << kvdb_1_server_data.version << std::endl;
            iniFileWriter << "lastEntryDate = " << kvdb_1_server_data.lastEntryDate << std::endl;
            iniFileWriter << "publicMeta_inHex = " << utils::Hex::from(kvdb_1_server_data.publicMeta.stdString()) << std::endl;
            iniFileWriter << "privateMeta_inHex = " << utils::Hex::from(kvdb_1_server_data.privateMeta.stdString()) << std::endl;
            iniFileWriter << "entries = " << kvdb_1_server_data.entries << std::endl;
            iniFileWriter << "statusCode = " << kvdb_1_server_data.statusCode << std::endl;
            iniFileWriter << "schemaVersion = " << kvdb_1_server_data.schemaVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(kvdb_1_server_data)) << std::endl;
            iniFileWriter << "uploaded_publicMeta_inHex = " << utils::Hex::from(kvdb_1_publicMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_privateMeta_inHex = " << utils::Hex::from(kvdb_1_privateMeta.stdString()) << std::endl;
            //Kvdb_2
            iniFileWriter << "[Kvdb_2]" << std::endl;
            iniFileWriter << "kvdbId = " << kvdb_2_server_data.kvdbId << std::endl;
            iniFileWriter << "contextId = " << kvdb_2_server_data.contextId << std::endl;
            iniFileWriter << "createDate = " << kvdb_2_server_data.createDate << std::endl;
            iniFileWriter << "creator = " << kvdb_2_server_data.creator << std::endl;
            iniFileWriter << "lastModificationDate = " << kvdb_2_server_data.lastModificationDate << std::endl;
            iniFileWriter << "lastModifier = " << kvdb_2_server_data.lastModifier << std::endl;
            iniFileWriter << "version = " << kvdb_2_server_data.version << std::endl;
            iniFileWriter << "lastEntryDate = " << kvdb_2_server_data.lastEntryDate << std::endl;
            iniFileWriter << "publicMeta_inHex = " << utils::Hex::from(kvdb_2_server_data.publicMeta.stdString()) << std::endl;
            iniFileWriter << "privateMeta_inHex = " << utils::Hex::from(kvdb_2_server_data.privateMeta.stdString()) << std::endl;
            iniFileWriter << "entries = " << kvdb_2_server_data.entries << std::endl;
            iniFileWriter << "statusCode = " << kvdb_2_server_data.statusCode << std::endl;
            iniFileWriter << "schemaVersion = " << kvdb_2_server_data.schemaVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(kvdb_2_server_data)) << std::endl;
            iniFileWriter << "uploaded_publicMeta_inHex = " << utils::Hex::from(kvdb_2_publicMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_privateMeta_inHex = " << utils::Hex::from(kvdb_2_privateMeta.stdString()) << std::endl;
            //Kvdb_3
            iniFileWriter << "[Kvdb_3]" << std::endl;
            iniFileWriter << "kvdbId = " << kvdb_3_server_data.kvdbId << std::endl;
            iniFileWriter << "contextId = " << kvdb_3_server_data.contextId << std::endl;
            iniFileWriter << "createDate = " << kvdb_3_server_data.createDate << std::endl;
            iniFileWriter << "creator = " << kvdb_3_server_data.creator << std::endl;
            iniFileWriter << "lastModificationDate = " << kvdb_3_server_data.lastModificationDate << std::endl;
            iniFileWriter << "lastModifier = " << kvdb_3_server_data.lastModifier << std::endl;
            iniFileWriter << "version = " << kvdb_3_server_data.version << std::endl;
            iniFileWriter << "lastEntryDate = " << kvdb_3_server_data.lastEntryDate << std::endl;
            iniFileWriter << "publicMeta_inHex = " << utils::Hex::from(kvdb_3_server_data.publicMeta.stdString()) << std::endl;
            iniFileWriter << "privateMeta_inHex = " << utils::Hex::from(kvdb_3_server_data.privateMeta.stdString()) << std::endl;
            iniFileWriter << "entries = " << kvdb_3_server_data.entries << std::endl;
            iniFileWriter << "statusCode = " << kvdb_3_server_data.statusCode << std::endl;
            iniFileWriter << "schemaVersion = " << kvdb_3_server_data.schemaVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(kvdb_3_server_data)) << std::endl;
            iniFileWriter << "uploaded_publicMeta_inHex = " << utils::Hex::from(kvdb_3_publicMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_privateMeta_inHex = " << utils::Hex::from(kvdb_3_privateMeta.stdString()) << std::endl;
            // SearchIndex 1
            iniFileWriter << "[SearchIndex_1]" << std::endl;
            iniFileWriter << "indexId = " << searchIndex_1_server_data.indexId << std::endl;
            iniFileWriter << "contextId = " << searchIndex_1_server_data.contextId << std::endl;
            iniFileWriter << "createDate = " << searchIndex_1_server_data.createDate << std::endl;
            iniFileWriter << "creator = " << searchIndex_1_server_data.creator << std::endl;
            iniFileWriter << "lastModificationDate = " << searchIndex_1_server_data.lastModificationDate << std::endl;
            iniFileWriter << "lastModifier = " << searchIndex_1_server_data.lastModifier << std::endl;
            iniFileWriter << "version = " << searchIndex_1_server_data.version << std::endl;
            iniFileWriter << "mode = " <<  static_cast<int64_t>(searchIndex_1_server_data.mode) << std::endl;
            iniFileWriter << "publicMeta_inHex = " << utils::Hex::from(searchIndex_1_server_data.publicMeta.stdString()) << std::endl;
            iniFileWriter << "privateMeta_inHex = " << utils::Hex::from(searchIndex_1_server_data.privateMeta.stdString()) << std::endl;
            iniFileWriter << "statusCode = " << searchIndex_1_server_data.statusCode << std::endl;
            iniFileWriter << "schemaVersion = " << searchIndex_1_server_data.schemaVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(searchIndex_1_server_data)) << std::endl;
            iniFileWriter << "uploaded_publicMeta_inHex = " << utils::Hex::from(searchIndex_1_publicMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_privateMeta_inHex = " << utils::Hex::from(searchIndex_1_privateMeta.stdString()) << std::endl;

            iniFileWriter << "doc_1_id = " << searchIndex_1_doc_1_id << std::endl;
            iniFileWriter << "doc_1_name = " << searchIndex_1_doc_1_name << std::endl;
            iniFileWriter << "doc_1_content = " << searchIndex_1_doc_1_content << std::endl;
            iniFileWriter << "doc_2_id = " << searchIndex_1_doc_2_id << std::endl;
            iniFileWriter << "doc_2_name = " << searchIndex_1_doc_2_name << std::endl;
            iniFileWriter << "doc_2_content = " << searchIndex_1_doc_2_content << std::endl;
            iniFileWriter << "docs_common_content_part = " << searchIndex_1_docs_common_content_part << std::endl;
            // SearchIndex 2
            iniFileWriter << "[SearchIndex_2]" << std::endl;
            iniFileWriter << "indexId = " << searchIndex_2_server_data.indexId << std::endl;
            iniFileWriter << "contextId = " << searchIndex_2_server_data.contextId << std::endl;
            iniFileWriter << "createDate = " << searchIndex_2_server_data.createDate << std::endl;
            iniFileWriter << "creator = " << searchIndex_2_server_data.creator << std::endl;
            iniFileWriter << "lastModificationDate = " << searchIndex_2_server_data.lastModificationDate << std::endl;
            iniFileWriter << "lastModifier = " << searchIndex_2_server_data.lastModifier << std::endl;
            iniFileWriter << "version = " << searchIndex_2_server_data.version << std::endl;
            iniFileWriter << "mode = " << static_cast<int64_t>(searchIndex_2_server_data.mode) << std::endl;
            iniFileWriter << "publicMeta_inHex = " << utils::Hex::from(searchIndex_2_server_data.publicMeta.stdString()) << std::endl;
            iniFileWriter << "privateMeta_inHex = " << utils::Hex::from(searchIndex_2_server_data.privateMeta.stdString()) << std::endl;
            iniFileWriter << "statusCode = " << searchIndex_2_server_data.statusCode << std::endl;
            iniFileWriter << "schemaVersion = " << searchIndex_2_server_data.schemaVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(searchIndex_2_server_data)) << std::endl;
            iniFileWriter << "uploaded_publicMeta_inHex = " << utils::Hex::from(searchIndex_2_publicMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_privateMeta_inHex = " << utils::Hex::from(searchIndex_2_privateMeta.stdString()) << std::endl;
            // SearchIndex 3
            iniFileWriter << "[SearchIndex_3]" << std::endl;
            iniFileWriter << "indexId = " << searchIndex_3_server_data.indexId << std::endl;
            iniFileWriter << "contextId = " << searchIndex_3_server_data.contextId << std::endl;
            iniFileWriter << "createDate = " << searchIndex_3_server_data.createDate << std::endl;
            iniFileWriter << "creator = " << searchIndex_3_server_data.creator << std::endl;
            iniFileWriter << "lastModificationDate = " << searchIndex_3_server_data.lastModificationDate << std::endl;
            iniFileWriter << "lastModifier = " << searchIndex_3_server_data.lastModifier << std::endl;
            iniFileWriter << "version = " << searchIndex_3_server_data.version << std::endl;
            iniFileWriter << "mode = " << static_cast<int64_t>(searchIndex_3_server_data.mode) << std::endl;
            iniFileWriter << "publicMeta_inHex = " << utils::Hex::from(searchIndex_3_server_data.publicMeta.stdString()) << std::endl;
            iniFileWriter << "privateMeta_inHex = " << utils::Hex::from(searchIndex_3_server_data.privateMeta.stdString()) << std::endl;
            iniFileWriter << "statusCode = " << searchIndex_3_server_data.statusCode << std::endl;
            iniFileWriter << "schemaVersion = " << searchIndex_3_server_data.schemaVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(searchIndex_3_server_data)) << std::endl;
            iniFileWriter << "uploaded_publicMeta_inHex = " << utils::Hex::from(searchIndex_3_publicMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_privateMeta_inHex = " << utils::Hex::from(searchIndex_3_privateMeta.stdString()) << std::endl;
            // SqlDatabase 1
            iniFileWriter << "[SqlDatabase_1]" << std::endl;
            iniFileWriter << "sqlDatabaseId = " << sqlDatabase_1_server_data.sqlDatabaseId << std::endl;
            iniFileWriter << "contextId = " << sqlDatabase_1_server_data.contextId << std::endl;
            iniFileWriter << "createDate = " << sqlDatabase_1_server_data.createDate << std::endl;
            iniFileWriter << "creator = " << sqlDatabase_1_server_data.creator << std::endl;
            iniFileWriter << "lastModificationDate = " << sqlDatabase_1_server_data.lastModificationDate << std::endl;
            iniFileWriter << "lastModifier = " << sqlDatabase_1_server_data.lastModifier << std::endl;
            iniFileWriter << "version = " << sqlDatabase_1_server_data.version << std::endl;
            iniFileWriter << "publicMeta_inHex = " << utils::Hex::from(sqlDatabase_1_server_data.publicMeta.stdString()) << std::endl;
            iniFileWriter << "privateMeta_inHex = " << utils::Hex::from(sqlDatabase_1_server_data.privateMeta.stdString()) << std::endl;
            iniFileWriter << "statusCode = " << sqlDatabase_1_server_data.statusCode << std::endl;
            iniFileWriter << "schemaVersion = " << sqlDatabase_1_server_data.schemaVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(sqlDatabase_1_server_data)) << std::endl;
            iniFileWriter << "uploaded_publicMeta_inHex = " << utils::Hex::from(sqlDatabase_1_publicMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_privateMeta_inHex = " << utils::Hex::from(sqlDatabase_1_privateMeta.stdString()) << std::endl;

            iniFileWriter << "table_1_name = " << sqlDatabase_1_table_1_name << std::endl;
            iniFileWriter << "table_1_field_1 = " << sqlDatabase_1_table_1_field_1 << std::endl;
            iniFileWriter << "table_1_field_1_type = " << sqlDatabase_1_table_1_field_1_type << std::endl;
            iniFileWriter << "table_1_field_2 = " << sqlDatabase_1_table_1_field_2 << std::endl;
            iniFileWriter << "table_1_field_2_type = " << sqlDatabase_1_table_1_field_2_type << std::endl;
            iniFileWriter << "table_1_field_3 = " << sqlDatabase_1_table_1_field_3 << std::endl;
            iniFileWriter << "table_1_field_3_type = " << sqlDatabase_1_table_1_field_3_type << std::endl;
            iniFileWriter << "table_1_entry_1_field_1 = " << sqlDatabase_1_table_1_entry_1_field_1 << std::endl;
            iniFileWriter << "table_1_entry_1_field_2 = " << sqlDatabase_1_table_1_entry_1_field_2 << std::endl;
            iniFileWriter << "table_1_entry_1_field_3 = " << sqlDatabase_1_table_1_entry_1_field_3 << std::endl;
            iniFileWriter << "table_1_entry_2_field_1 = " << sqlDatabase_1_table_1_entry_2_field_1 << std::endl;
            iniFileWriter << "table_1_entry_2_field_2 = " << sqlDatabase_1_table_1_entry_2_field_2 << std::endl;
            iniFileWriter << "table_1_entry_2_field_3 = " << sqlDatabase_1_table_1_entry_2_field_3 << std::endl;
            // SqlDatabase 2
            iniFileWriter << "[SqlDatabase_2]" << std::endl;
            iniFileWriter << "sqlDatabaseId = " << sqlDatabase_2_server_data.sqlDatabaseId << std::endl;
            iniFileWriter << "contextId = " << sqlDatabase_2_server_data.contextId << std::endl;
            iniFileWriter << "createDate = " << sqlDatabase_2_server_data.createDate << std::endl;
            iniFileWriter << "creator = " << sqlDatabase_2_server_data.creator << std::endl;
            iniFileWriter << "lastModificationDate = " << sqlDatabase_2_server_data.lastModificationDate << std::endl;
            iniFileWriter << "lastModifier = " << sqlDatabase_2_server_data.lastModifier << std::endl;
            iniFileWriter << "version = " << sqlDatabase_2_server_data.version << std::endl;
            iniFileWriter << "publicMeta_inHex = " << utils::Hex::from(sqlDatabase_2_server_data.publicMeta.stdString()) << std::endl;
            iniFileWriter << "privateMeta_inHex = " << utils::Hex::from(sqlDatabase_2_server_data.privateMeta.stdString()) << std::endl;
            iniFileWriter << "statusCode = " << sqlDatabase_2_server_data.statusCode << std::endl;
            iniFileWriter << "schemaVersion = " << sqlDatabase_2_server_data.schemaVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(sqlDatabase_2_server_data)) << std::endl;
            iniFileWriter << "uploaded_publicMeta_inHex = " << utils::Hex::from(sqlDatabase_2_publicMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_privateMeta_inHex = " << utils::Hex::from(sqlDatabase_2_privateMeta.stdString()) << std::endl;
            // SqlDatabase 3
            iniFileWriter << "[SqlDatabase_3]" << std::endl;
            iniFileWriter << "sqlDatabaseId = " << sqlDatabase_3_server_data.sqlDatabaseId << std::endl;
            iniFileWriter << "contextId = " << sqlDatabase_3_server_data.contextId << std::endl;
            iniFileWriter << "createDate = " << sqlDatabase_3_server_data.createDate << std::endl;
            iniFileWriter << "creator = " << sqlDatabase_3_server_data.creator << std::endl;
            iniFileWriter << "lastModificationDate = " << sqlDatabase_3_server_data.lastModificationDate << std::endl;
            iniFileWriter << "lastModifier = " << sqlDatabase_3_server_data.lastModifier << std::endl;
            iniFileWriter << "version = " << sqlDatabase_3_server_data.version << std::endl;
            iniFileWriter << "publicMeta_inHex = " << utils::Hex::from(sqlDatabase_3_server_data.publicMeta.stdString()) << std::endl;
            iniFileWriter << "privateMeta_inHex = " << utils::Hex::from(sqlDatabase_3_server_data.privateMeta.stdString()) << std::endl;
            iniFileWriter << "statusCode = " << sqlDatabase_3_server_data.statusCode << std::endl;
            iniFileWriter << "schemaVersion = " << sqlDatabase_3_server_data.schemaVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(sqlDatabase_3_server_data)) << std::endl;
            iniFileWriter << "uploaded_publicMeta_inHex = " << utils::Hex::from(sqlDatabase_3_publicMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_privateMeta_inHex = " << utils::Hex::from(sqlDatabase_3_privateMeta.stdString()) << std::endl;
            
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
            iniFileWriter << "schemaVersion = " << message_1_server_data.schemaVersion << std::endl;
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
            iniFileWriter << "schemaVersion = " << message_2_server_data.schemaVersion << std::endl;
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
            iniFileWriter << "schemaVersion = " << file_1_server_metaData.schemaVersion << std::endl;
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
            iniFileWriter << "schemaVersion = " << file_2_server_metaData.schemaVersion << std::endl;
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
            iniFileWriter << "schemaVersion = " << entry_1_server_data.schemaVersion << std::endl;
            iniFileWriter << "file_0_info_storeId = " << entry_1_server_data.files[0].info.storeId << std::endl;
            iniFileWriter << "file_0_info_fileId = " << entry_1_server_data.files[0].info.fileId << std::endl;
            iniFileWriter << "file_0_info_createDate = " << entry_1_server_data.files[0].info.createDate << std::endl;
            iniFileWriter << "file_0_info_author = " << entry_1_server_data.files[0].info.author << std::endl;
            iniFileWriter << "file_0_authorPubKey = " << entry_1_server_data.files[0].authorPubKey << std::endl;
            iniFileWriter << "file_0_statusCode = " << entry_1_server_data.files[0].statusCode << std::endl;
            iniFileWriter << "file_0_schemaVersion = " << entry_1_server_data.files[0].schemaVersion << std::endl;
            iniFileWriter << "file_0_publicMeta_inHex = " << utils::Hex::from(entry_1_server_data.files[0].publicMeta.stdString()) << std::endl;
            iniFileWriter << "file_0_privateMeta_inHex = " << utils::Hex::from(entry_1_server_data.files[0].privateMeta.stdString()) << std::endl;
            iniFileWriter << "file_0_size = " << entry_1_server_data.files[0].size << std::endl;

            iniFileWriter << "file_1_info_storeId = " << entry_1_server_data.files[1].info.storeId << std::endl;
            iniFileWriter << "file_1_info_fileId = " << entry_1_server_data.files[1].info.fileId << std::endl;
            iniFileWriter << "file_1_info_createDate = " << entry_1_server_data.files[1].info.createDate << std::endl;
            iniFileWriter << "file_1_info_author = " << entry_1_server_data.files[1].info.author << std::endl;
            iniFileWriter << "file_1_authorPubKey = " << entry_1_server_data.files[1].authorPubKey << std::endl;
            iniFileWriter << "file_1_statusCode = " << entry_1_server_data.files[1].statusCode << std::endl;
            iniFileWriter << "file_0_schemaVersion = " << entry_1_server_data.files[1].schemaVersion << std::endl;
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
            iniFileWriter << "schemaVersion = " << entry_2_server_data.schemaVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(entry_2_server_data)) << std::endl;

            iniFileWriter << "uploaded_data_inHex = " << utils::Hex::from(entry_2_data) << std::endl;
            // KvdbEntry_1
            iniFileWriter << "[KvdbEntry_1]" << std::endl;
            iniFileWriter << "info_kvdbId = " << kvdb_entry_1_server_data.info.kvdbId << std::endl;
            iniFileWriter << "info_key = " << kvdb_entry_1_server_data.info.key << std::endl;
            iniFileWriter << "info_createDate = " << kvdb_entry_1_server_data.info.createDate << std::endl;
            iniFileWriter << "info_author = " << kvdb_entry_1_server_data.info.author << std::endl;
            iniFileWriter << "publicMeta_inHex = " << utils::Hex::from(kvdb_entry_1_server_data.publicMeta.stdString()) << std::endl;
            iniFileWriter << "privateMeta_inHex = " << utils::Hex::from(kvdb_entry_1_server_data.privateMeta.stdString()) << std::endl;
            iniFileWriter << "data_inHex = " << utils::Hex::from(kvdb_entry_1_server_data.data.stdString()) << std::endl;
            iniFileWriter << "authorPubKey = " << kvdb_entry_1_server_data.authorPubKey << std::endl;
            iniFileWriter << "statusCode = " << kvdb_entry_1_server_data.statusCode << std::endl;
            iniFileWriter << "schemaVersion = " << kvdb_entry_1_server_data.schemaVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(kvdb_entry_1_server_data)) << std::endl;
            iniFileWriter << "uploaded_publicMeta_inHex = " << utils::Hex::from(kvdb_entry_1_publicMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_privateMeta_inHex = " << utils::Hex::from(kvdb_entry_1_privateMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_data_inHex = " << utils::Hex::from(kvdb_entry_1_data.stdString()) << std::endl;
            // KvdbEntry_2
            iniFileWriter << "[KvdbEntry_2]" << std::endl;
            iniFileWriter << "info_kvdbId = " << kvdb_entry_2_server_data.info.kvdbId << std::endl;
            iniFileWriter << "info_key = " << kvdb_entry_2_server_data.info.key << std::endl;
            iniFileWriter << "info_createDate = " << kvdb_entry_2_server_data.info.createDate << std::endl;
            iniFileWriter << "info_author = " << kvdb_entry_2_server_data.info.author << std::endl;
            iniFileWriter << "publicMeta_inHex = " << utils::Hex::from(kvdb_entry_2_server_data.publicMeta.stdString()) << std::endl;
            iniFileWriter << "privateMeta_inHex = " << utils::Hex::from(kvdb_entry_2_server_data.privateMeta.stdString()) << std::endl;
            iniFileWriter << "data_inHex = " << utils::Hex::from(kvdb_entry_2_server_data.data.stdString()) << std::endl;
            iniFileWriter << "authorPubKey = " << kvdb_entry_2_server_data.authorPubKey << std::endl;
            iniFileWriter << "statusCode = " << kvdb_entry_2_server_data.statusCode << std::endl;
            iniFileWriter << "schemaVersion = " << kvdb_entry_2_server_data.schemaVersion << std::endl;
            iniFileWriter << "JSON_data = " << utils::Utils::stringifyVar(_serializer.serialize(kvdb_entry_2_server_data)) << std::endl;
            iniFileWriter << "uploaded_publicMeta_inHex = " << utils::Hex::from(kvdb_entry_2_publicMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_privateMeta_inHex = " << utils::Hex::from(kvdb_entry_2_privateMeta.stdString()) << std::endl;
            iniFileWriter << "uploaded_data_inHex = " << utils::Hex::from(kvdb_entry_2_data.stdString()) << std::endl;
            iniFileWriter.close();
            
        }
        LOG_INFO("Writing data to json file")
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
            Poco::JSON::Object::Ptr data_kvdb_1 = new Poco::JSON::Object();
            data_kvdb_1->set("server_data", (_serializer.serialize(kvdb_1_server_data)));
            data_kvdb_1->set("uploaded_publicMeta_inBase64", utils::Base64::from(kvdb_1_publicMeta.stdString()));
            data_kvdb_1->set("uploaded_privateMeta_inBase64", utils::Base64::from(kvdb_1_privateMeta.stdString()));
            data->set("Kvdb_1", data_kvdb_1);
            Poco::JSON::Object::Ptr data_kvdb_2 = new Poco::JSON::Object();
            data_kvdb_2->set("server_data", (_serializer.serialize(kvdb_2_server_data)));
            data_kvdb_2->set("uploaded_publicMeta_inBase64", utils::Base64::from(kvdb_2_publicMeta.stdString()));
            data_kvdb_2->set("uploaded_privateMeta_inBase64", utils::Base64::from(kvdb_2_privateMeta.stdString()));
            data->set("Kvdb_2", data_kvdb_2);
            Poco::JSON::Object::Ptr data_kvdb_3 = new Poco::JSON::Object();
            data_kvdb_3->set("server_data", (_serializer.serialize(kvdb_3_server_data)));
            data_kvdb_3->set("uploaded_publicMeta_inBase64", utils::Base64::from(kvdb_3_publicMeta.stdString()));
            data_kvdb_3->set("uploaded_privateMeta_inBase64", utils::Base64::from(kvdb_3_privateMeta.stdString()));
            data->set("Kvdb_3", data_kvdb_3);
            Poco::JSON::Object::Ptr search_index_1 = new Poco::JSON::Object();
            search_index_1->set("server_data", (_serializer.serialize(searchIndex_1_server_data)));
            search_index_1->set("uploaded_publicMeta_inBase64", utils::Base64::from(searchIndex_1_publicMeta.stdString()));
            search_index_1->set("uploaded_privateMeta_inBase64", utils::Base64::from(searchIndex_1_privateMeta.stdString()));
            search_index_1->set("doc_1_id", searchIndex_1_doc_1_id);
            search_index_1->set("doc_1_name", searchIndex_1_doc_1_name);
            search_index_1->set("doc_1_content", searchIndex_1_doc_1_content);
            search_index_1->set("doc_2_id", searchIndex_1_doc_2_id);
            search_index_1->set("doc_2_name", searchIndex_1_doc_2_name);
            search_index_1->set("doc_2_content", searchIndex_1_doc_2_content);
            search_index_1->set("docs_common_content_part", searchIndex_1_docs_common_content_part);
            data->set("SearchIndex_1", search_index_1);
            Poco::JSON::Object::Ptr search_index_2 = new Poco::JSON::Object();
            search_index_2->set("server_data", (_serializer.serialize(searchIndex_2_server_data)));
            search_index_2->set("uploaded_publicMeta_inBase64", utils::Base64::from(searchIndex_2_publicMeta.stdString()));
            search_index_2->set("uploaded_privateMeta_inBase64", utils::Base64::from(searchIndex_2_privateMeta.stdString()));
            data->set("SearchIndex_2", search_index_2);
            Poco::JSON::Object::Ptr search_index_3 = new Poco::JSON::Object();
            search_index_3->set("server_data", (_serializer.serialize(searchIndex_3_server_data)));
            search_index_3->set("uploaded_publicMeta_inBase64", utils::Base64::from(searchIndex_3_publicMeta.stdString()));
            search_index_3->set("uploaded_privateMeta_inBase64", utils::Base64::from(searchIndex_3_privateMeta.stdString()));
            data->set("SearchIndex_3", search_index_3);
            Poco::JSON::Object::Ptr sql_database_1 = new Poco::JSON::Object();
            sql_database_1->set("server_data", (_serializer.serialize(sqlDatabase_1_server_data)));
            sql_database_1->set("uploaded_publicMeta_inBase64", utils::Base64::from(sqlDatabase_1_publicMeta.stdString()));
            sql_database_1->set("uploaded_privateMeta_inBase64", utils::Base64::from(sqlDatabase_1_privateMeta.stdString()));
            sql_database_1->set("table_1_name", sqlDatabase_1_table_1_name);
            sql_database_1->set("table_1_field_1", sqlDatabase_1_table_1_field_1);
            sql_database_1->set("table_1_field_1_type", static_cast<int64_t>(sqlDatabase_1_table_1_field_1_type));
            sql_database_1->set("table_1_field_2", sqlDatabase_1_table_1_field_2);
            sql_database_1->set("table_1_field_2_type", static_cast<int64_t>(sqlDatabase_1_table_1_field_2_type));
            sql_database_1->set("table_1_field_3", sqlDatabase_1_table_1_field_3);
            sql_database_1->set("table_1_field_3_type", static_cast<int64_t>(sqlDatabase_1_table_1_field_3_type));
            sql_database_1->set("table_1_entry_1_field_1", sqlDatabase_1_table_1_entry_1_field_1);
            sql_database_1->set("table_1_entry_1_field_2", sqlDatabase_1_table_1_entry_1_field_2);
            sql_database_1->set("table_1_entry_1_field_3", sqlDatabase_1_table_1_entry_1_field_3);
            sql_database_1->set("table_1_entry_2_field_1", sqlDatabase_1_table_1_entry_2_field_1);
            sql_database_1->set("table_1_entry_2_field_2", sqlDatabase_1_table_1_entry_2_field_2);
            sql_database_1->set("table_1_entry_2_field_3", sqlDatabase_1_table_1_entry_2_field_3);
            data->set("SqlDatabase_1", sql_database_1);
            Poco::JSON::Object::Ptr sql_database_2 = new Poco::JSON::Object();
            sql_database_2->set("server_data", (_serializer.serialize(sqlDatabase_2_server_data)));
            sql_database_2->set("uploaded_publicMeta_inBase64", utils::Base64::from(sqlDatabase_2_publicMeta.stdString()));
            sql_database_2->set("uploaded_privateMeta_inBase64", utils::Base64::from(sqlDatabase_2_privateMeta.stdString()));
            data->set("SqlDatabase_2", sql_database_2);
            Poco::JSON::Object::Ptr sql_database_3 = new Poco::JSON::Object();
            sql_database_3->set("server_data", (_serializer.serialize(sqlDatabase_2_server_data)));
            sql_database_3->set("uploaded_publicMeta_inBase64", utils::Base64::from(sqlDatabase_2_publicMeta.stdString()));
            sql_database_3->set("uploaded_privateMeta_inBase64", utils::Base64::from(sqlDatabase_2_privateMeta.stdString()));
            data->set("SqlDatabase_3", sql_database_3);
            

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

            Poco::JSON::Object::Ptr data_kvdb_entry_1 = new Poco::JSON::Object();
            data_kvdb_entry_1->set("server_data", (_serializer.serialize(kvdb_entry_1_server_data)));
            data_kvdb_entry_1->set("uploaded_publicMeta_inBase64", utils::Base64::from(kvdb_entry_1_publicMeta.stdString()));
            data_kvdb_entry_1->set("uploaded_privateMeta_inBase64", utils::Base64::from(kvdb_entry_1_privateMeta.stdString()));
            data_kvdb_entry_1->set("uploaded_data_inBase64", utils::Base64::from(kvdb_entry_1_data.stdString()));
            data->set("KvdbEntry_1", data_kvdb_entry_1);
            Poco::JSON::Object::Ptr data_kvdb_entry_2 = new Poco::JSON::Object();
            data_kvdb_entry_2->set("server_data", (_serializer.serialize(kvdb_entry_2_server_data)));
            data_kvdb_entry_2->set("uploaded_publicMeta_inBase64", utils::Base64::from(kvdb_entry_2_publicMeta.stdString()));
            data_kvdb_entry_2->set("uploaded_privateMeta_inBase64", utils::Base64::from(kvdb_entry_2_privateMeta.stdString()));
            data_kvdb_entry_2->set("uploaded_data_inBase64", utils::Base64::from(kvdb_entry_2_data.stdString()));
            data->set("KvdbEntry_2", data_kvdb_entry_2);

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