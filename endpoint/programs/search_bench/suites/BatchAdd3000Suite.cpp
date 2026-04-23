#include "BatchAdd3000Suite.hpp"

#include "SearchBenchHelpers.hpp"

#include <chrono>
#include <iostream>

namespace search_bench {

namespace {

constexpr std::size_t kMaxDocumentsToLoad = 100;

}  // namespace

void runBatchAdd3000Suite(RuntimeContext& runtime) {
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


    auto documentsToAdd = loadDocumentsFromJsonDirectory(
        runtime.options.messagesDir,
        kMaxDocumentsToLoad
    );
    std::cout << "Adding 3000 documents...\n";

    const auto batchAddStart = std::chrono::steady_clock::now();
    for (int i = 0; i < 30; i++) {
        runtime.searchApi.addDocuments(indexHandle, documentsToAdd);
    }
    const auto batchAddEnd = std::chrono::steady_clock::now();
    const auto batchAddDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        batchAddEnd - batchAddStart
    ).count();

    std::cout << "Adding " << documentsToAdd.size() * 30
              << " messages (as batch) - took: " << batchAddDurationMs << " ms\n";
    std::cout << "IndexId: " << indexId << '\n';
    runtime.searchApi.closeSearchIndex(indexHandle);
}

}  // namespace search_bench
