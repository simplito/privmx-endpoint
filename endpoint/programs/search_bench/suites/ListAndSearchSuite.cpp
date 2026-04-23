#include "ListAndSearchSuite.hpp"

#include "SearchBenchHelpers.hpp"

#include <chrono>
#include <iostream>

namespace search_bench {

namespace {

constexpr std::size_t kMaxDocumentsToLoad = 100;
constexpr int64_t kDocumentListLimit = 100;
constexpr int64_t kSearchResultLimit = 100;
constexpr const char* kDefaultSearchQuery = "is";

}  // namespace

void runListAndSearchSuite(RuntimeContext& runtime) {
    // 1000 msgs index: 69e8db8d342e11bdac7522d1
    // 2000 msgs index: 69e8db908ebc3972d2ad4881
    // 3000 msgs index: 69e8db97c08f34d4d8e116e8
    // 100k messages index: 69e92d861e122afaf621e97b

    auto usersWithPubKey = getContextUsersWithPubKeys(runtime);

    auto existingIndexes = runtime.searchApi.listSearchIndexes(runtime.options.contextId, {0, 1, "desc"});
    auto existingIndexId = runtime.options.searchIndex;
    auto reopenedIndexHandle = runtime.searchApi.openSearchIndex(existingIndexId);

    privmx::endpoint::core::PagingQuery pagingQuery{
        .skip = 0,
        .limit = kSearchResultLimit,
        .sortOrder = "asc",
    };

    std::cout << "Total documents in Index: " << runtime.searchApi.listDocuments(reopenedIndexHandle, pagingQuery).totalAvailable << '\n';

    const auto searchStart = std::chrono::steady_clock::now();
    auto result = runtime.searchApi.searchDocuments(reopenedIndexHandle, kDefaultSearchQuery, pagingQuery);
    const auto searchEnd = std::chrono::steady_clock::now();
    const auto searchDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        searchEnd - searchStart
    ).count();

    std::cout << "Search query took: " << searchDurationMs << " ms\n";
    // for (const auto& document : result.readItems) {
    //     std::cout << document.name << ": " << document.content << '\n';
    // }
    std::cout << "Found documents: " << result.totalAvailable << '\n';
    runtime.searchApi.closeSearchIndex(reopenedIndexHandle);
    std::cout << "Done!\n";
}

}  // namespace search_bench
