#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include <vector>
#include <thread>
#include <chrono>
#include <filesystem>
#include <functional>
#include <cstdlib>
#include <stdexcept>
#include <random>
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
// #include <privmx/utils/IniFileReader.hpp>
#include <privmx/endpoint/core/Exception.hpp>

#include <privmx/endpoint/core/Config.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/kvdb/KvdbApi.hpp>
#include <privmx/endpoint/search/SearchApi.hpp>
#include <privmx/utils/PrivmxException.hpp>

using namespace std;
using namespace privmx::endpoint;
namespace fs = std::filesystem;

static vector<string_view> getParamsList(int argc, char* argv[]) {
    vector<string_view> args(argv + 1, argv + argc);
    return args;
}

static std::vector<std::string> readTextFileLines(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        throw std::runtime_error("Unable to open file: " + filePath);
    }

    std::vector<std::string> lines;
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.empty()) {
            continue;
        }
        lines.push_back(line);
    }

    return lines;
}

static void processAllTxtFiles(
    const std::string& directoryPath,
    const std::function<void(std::string content)>& processContent
) {
    if (!fs::exists(directoryPath)) {
        throw std::runtime_error("Directory does not exist: " + directoryPath);
    }
    if (!fs::is_directory(directoryPath)) {
        throw std::runtime_error("Path is not a directory: " + directoryPath);
    }

    for (const auto& entry : fs::directory_iterator(directoryPath)) {
        if (!entry.is_regular_file() || entry.path().extension() != ".txt") {
            continue;
        }

        std::ifstream file(entry.path());
        if (!file.is_open()) {
            throw std::runtime_error("Unable to open file: " + entry.path().string());
        }

        std::ostringstream content;
        content << file.rdbuf();
        processContent(content.str());
    }
}

static std::vector<std::string> generateMessages(const std::vector<std::string>& words, int num) {
    if (words.empty()) {
        throw std::runtime_error("Words list cannot be empty");
    }
    if (num < 0) {
        throw std::runtime_error("Number of messages cannot be negative");
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> messageLengthDist(5, 20);
    std::uniform_int_distribution<std::size_t> wordIndexDist(0, words.size() - 1);

    std::vector<std::string> messages;
    messages.reserve(num);

    for (int i = 0; i < num; ++i) {
        const int messageLength = messageLengthDist(gen);
        std::ostringstream message;

        for (int j = 0; j < messageLength; ++j) {
            if (j > 0) {
                message << ' ';
            }
            message << words[wordIndexDist(gen)];
        }

        messages.push_back(message.str());
    }

    return messages;
}

int main(int argc, char** argv) {
    auto params = getParamsList(argc, argv);
    if(params.size() != 5) {
        std::cout << "Invalid params. Required params are: 'PrivKey', 'SolutionId', 'BridgeUrl', 'ContextId', 'docs_dir_path'" << std::endl;
        return -1;
    }
    std::string privKey = {params[0].begin(),  params[0].end()};
    std::string solutionId = {params[1].begin(),  params[1].end()};
    std::string bridgeUrl = {params[2].begin(),  params[2].end()};
    std::string contextId = {params[3].begin(),  params[3].end()};
    std::string docsDir = {params[4].begin(),  params[4].end()};

    try {
        std::cout << "Reading words from: " << docsDir << std::endl;
        auto words = readTextFileLines(docsDir + "/" + "common_words_500.txt");
        std::cout << "Words count: " << words.size() << std::endl;

        core::Connection connection = core::Connection::connect(
            privKey, 
            solutionId, 
            bridgeUrl
        );
        kvdb::KvdbApi kvdb_api = kvdb::KvdbApi::create(connection);
        store::StoreApi store_api = store::StoreApi::create(connection);
        search::SearchApi search_api = search::SearchApi::create(connection, store_api, kvdb_api);


        auto contextUsersInfo = connection.listContextUsers(contextId, {0, 100, "asc"});
        std::vector<core::UserWithPubKey> usersWithPubKey = {};
        for(const auto& userInfo : contextUsersInfo.readItems) {
            usersWithPubKey.push_back(userInfo.user);
        }

        // auto index {search_api.createSearchIndex(contextId, usersWithPubKey, usersWithPubKey, {}, {}, search::IndexMode::WITH_CONTENT) };
        // auto indexHandle {search_api.openSearchIndex(index)};

        std::cout << "Adding docs from: " << docsDir << " to the index..." << std::endl;
        int id = 1;

        // processAllTxtFiles(docsDir + "/rfc", [&](std::string content) {
        //     if (id > 10) return;
        //     std::string name = "name_" + std::to_string(id++);
        //     std::cout << "Adding doc: " << name << std::endl;
        //     search_api.addDocument(indexHandle, name, content);
        // });

        const int batchCount = 1;
        const int messagesPerBatch = 100;
        long long totalBatchAddDurationMs = 0;
        // const auto searchStart100 = std::chrono::steady_clock::now();
        // for (int i = 0; i < batchCount; i++) {
        //     auto randomMessages = generateMessages(words, messagesPerBatch);
        //     const auto searchStart = std::chrono::steady_clock::now();
        //     for (auto message : randomMessages) {
        //         std::string name = "name_" + std::to_string(id++);
        //         std::cout << "Adding message: " << name << std::endl;
        //         search_api.addDocument(indexHandle, name, message);
        //     }
        //     const auto searchEnd = std::chrono::steady_clock::now();
        //     const auto searchDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(searchEnd - searchStart).count();
        //     totalBatchAddDurationMs += searchDurationMs;
        //     const auto totalElapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(searchEnd - searchStart100).count();
        //     std::cout << "Adding " << messagesPerBatch << " messages - took: " << searchDurationMs << " ms" << std::endl;
        //     std::cout << "Average add time per "<< messagesPerBatch<<"-message batch after batch " << (i + 1) << ": "
        //               << (static_cast<double>(totalBatchAddDurationMs) / (i + 1)) << " ms" << std::endl;
        //     std::cout << "Average total operation time per "<<messagesPerBatch<<"-message batch after batch " << (i + 1) << ": "
        //               << (static_cast<double>(totalElapsedMs) / (i + 1)) << " ms" << std::endl;
        //
        // }
        // const auto searchEnd100 = std::chrono::steady_clock::now();
        // const auto searchDurationMs100 = std::chrono::duration_cast<std::chrono::milliseconds>(searchEnd100 - searchStart100).count();
        // std::cout << "Adding "<<(messagesPerBatch * batchCount) <<" messages - took: " << searchDurationMs100 << " ms" << std::endl;
        // std::cout << "Average add time per "<<messagesPerBatch<<"-message batch: " << (static_cast<double>(totalBatchAddDurationMs) / batchCount) << " ms" << std::endl;
        // std::cout << "Average total operation time per "<<messagesPerBatch<<"-message batch: " << (static_cast<double>(searchDurationMs100) / batchCount) << " ms" << std::endl;




            // auto randomMessagesBatch = generateMessages(words, messagesPerBatch);
            // std::vector<search::NewDocument> documentsToAdd {};
            // int nameId = 1;
            // for (auto doc : randomMessagesBatch) {
            //     std::string name = "name_" + std::to_string(nameId++);
            //     documentsToAdd.push_back({name, doc});
            // }
            // const auto batchAddStart = std::chrono::steady_clock::now();
            // search_api.addDocuments(indexHandle, documentsToAdd);
            //
            // const auto batchAddEnd = std::chrono::steady_clock::now();
            // const auto batchAddDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(batchAddEnd - batchAddStart).count();
            //
            // std::cout << "Adding " << messagesPerBatch << " messages (as batch) - took: " << batchAddDurationMs << " ms" << std::endl;

            // auto added = search_api.listDocuments(indexHandle, {0, 100, "desc"});

        // std::cout << "Added docs:" << std::endl;
        // for (auto doc : added.readItems) {
        //     std::cout << doc.name << ": " << doc.content << std::endl;
        // }
        // std::cout << "Added docs count: " << added.readItems.size() << std::endl;

        // get existing index
        auto existingIndexes = search_api.listSearchIndexes(contextId, {0, 1, "desc"});
        auto existingIndex = existingIndexes.readItems[0];
        auto indexHandle2 = search_api.openSearchIndex(existingIndex.indexId);

        const auto searchStart = std::chrono::steady_clock::now();
        auto result = search_api.searchDocuments(indexHandle2, "is", {.skip = 0, .limit = 100, .sortOrder = "asc"});
        const auto searchEnd = std::chrono::steady_clock::now();
        const auto searchDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(searchEnd - searchStart).count();
        std::cout << "Search query took: " << searchDurationMs << " ms" << std::endl;
        for (const auto& doc : result.readItems) {
            std::cout << doc.name << ": " << doc.content << std::endl;
        }
        search_api.closeSearchIndex(indexHandle2);
        std::cout << "Done!" << std::endl;

    } catch (const core::Exception& e) {
        cerr << e.getFull() << endl;
    } catch (const privmx::utils::PrivmxException& e) {
        cerr << e.what() << endl;
        cerr << e.getData() << endl;
        cerr << e.getCode() << endl;
    } catch (const exception& e) {
        cerr << e.what() << endl;
    } catch (...) {
        cerr << "Error" << endl;
    }
    

    return 0;
}
