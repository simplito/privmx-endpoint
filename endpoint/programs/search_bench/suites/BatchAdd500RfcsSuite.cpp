#include "BatchAdd500RfcsSuite.hpp"

#include <Poco/Exception.h>

#include <chrono>
#include <iostream>
#include <exception>

#include "SearchBenchHelpers.hpp"

namespace search_bench {

namespace {

constexpr std::size_t kMaxDocumentsToLoad = 400;
// 1000 rfcs index: 69ea12a6342e11bdac75232c
}  // namespace

void runBatchAdd500RfcsSuite(RuntimeContext& runtime) {
    auto usersWithPubKey = getContextUsersWithPubKeys(runtime);

    auto indexId = runtime.searchApi.createSearchIndex(
        runtime.options.contextId,
        usersWithPubKey,
        usersWithPubKey,
        {},
        {},
        privmx::endpoint::search::IndexMode::WITH_CONTENT
    );
    auto indexHandle = runtime.searchApi.openSearchIndex(indexId);


    auto documentsToAdd = loadDocumentsFromRfcDirectory(
        runtime.options.rfcDir,
        kMaxDocumentsToLoad
    );
    std::cout << "Loaded " << documentsToAdd.size() << " RFC documents\n";
    std::cout << "Adding 1000 RFC documents...\n";

    const auto batchAddStart = std::chrono::steady_clock::now();
    int i = 0;
    int total = 0;
    int batchSize = 10;
    while (total < 500) {
        std::vector<privmx::endpoint::search::NewDocument> batch {};
        for (int j = 0; j < batchSize; j++) {
           batch.push_back(documentsToAdd[i+j]);
        }
        std::cout << "Adding batch " << batch.size() << " with document ID starting from: " << i << '\n';

        i += batchSize;
        if (i > documentsToAdd.size() - batchSize) {
            i = 0;
        }
        try {
            runtime.searchApi.addDocuments(indexHandle, batch);
            total += batchSize;
        } catch (...) {
            std::cout << "Failed to add batch " << batch.size() << '\n';
            for (int k = 0; k < batch.size(); ++k) {
                std::cout << "Failed to add document " << batch[k].name << '\n';
            }
        }
        std::cout << "Added total " << total << '\n';
    }
    const auto batchAddEnd = std::chrono::steady_clock::now();
    const auto batchAddDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        batchAddEnd - batchAddStart
    ).count();

    std::cout << "Adding " << total
              << " RFCs (as batch) - took: " << batchAddDurationMs << " ms\n";
    std::cout << "IndexId: " << indexId << '\n';
    runtime.searchApi.closeSearchIndex(indexHandle);
}

}  // namespace search_bench
