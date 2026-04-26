#include "ListAndSearchSuite.hpp"

#include "privmx/endpoint/store/ChunkDataProvider.hpp"

#include <chrono>
#include <iostream>

namespace search_bench {

namespace {

constexpr int64_t kSearchResultLimit = 100;
constexpr const char* kDefaultSearchQuery = "console";

int64_t openIndexForSuite(RuntimeContext& runtime, bool loadFully) {
    auto existingIndexId = runtime.options.searchIndex;
    // privmx::endpoint::store::ChunkDataProvider::resetTotalServerReadRequestCount();
    return runtime.searchApi.openSearchIndex(existingIndexId, loadFully);
}

privmx::endpoint::core::PagingQuery createPagingQuery() {
    privmx::endpoint::core::PagingQuery pagingQuery{
        .skip = 0,
        .limit = kSearchResultLimit,
        .sortOrder = "asc",
    };
    return pagingQuery;
}

void runListAndSearchSuite(RuntimeContext& runtime, bool loadFully) {
    // 1000 msgs index: 69e8db8d342e11bdac7522d1
    // 2000 msgs index: 69e8db908ebc3972d2ad4881
    // 3000 msgs index: 69e8db97c08f34d4d8e116e8
    // 100k messages index: 69e92d861e122afaf621e97b

    const auto existingIndexId = runtime.options.searchIndex;
    const auto reopenedIndexHandle = openIndexForSuite(runtime, loadFully);
    const auto pagingQuery = createPagingQuery();

    std::cout << "Index size: " << runtime.getSearchIndexSize(existingIndexId) << '\n';
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

}  // namespace

void runListSuite(RuntimeContext& runtime) {
    const auto existingIndexId = runtime.options.searchIndex;
    const auto reopenedIndexHandle = openIndexForSuite(runtime, false);
    const auto pagingQuery = createPagingQuery();

    std::cout << "Index size: " << runtime.getSearchIndexSize(existingIndexId) << '\n';

    const auto listStart = std::chrono::steady_clock::now();
    auto listResult = runtime.searchApi.listDocuments(reopenedIndexHandle, pagingQuery);
    const auto listEnd = std::chrono::steady_clock::now();
    const auto listDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        listEnd - listStart
    ).count();

    std::cout << "List documents took: " << listDurationMs << " ms\n";
    std::cout << "Total documents in Index: " << listResult.totalAvailable << '\n';
    std::cout << "Returned documents: " << listResult.readItems.size() << '\n';
    runtime.searchApi.closeSearchIndex(reopenedIndexHandle);
    std::cout << "Done!\n";
}

void runSearchSuite(RuntimeContext& runtime) {
    const auto existingIndexId = runtime.options.searchIndex;
    const auto reopenedIndexHandle = openIndexForSuite(runtime, false);
    const auto pagingQuery = createPagingQuery();

    std::cout << "Index size: " << runtime.getSearchIndexSize(existingIndexId) << '\n';

    const auto searchStart = std::chrono::steady_clock::now();
    auto result = runtime.searchApi.searchDocuments(reopenedIndexHandle, kDefaultSearchQuery, pagingQuery);
    const auto searchEnd = std::chrono::steady_clock::now();
    const auto searchDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        searchEnd - searchStart
    ).count();

    std::cout << "Search query took: " << searchDurationMs << " ms\n";
    std::cout << "Found documents: " << result.totalAvailable << '\n';
    runtime.searchApi.closeSearchIndex(reopenedIndexHandle);
    std::cout << "Done!\n";
}

void runListAndSearchSuite(RuntimeContext& runtime) {
    runListAndSearchSuite(runtime, false);
}

void runListAndSearchPreloadedSuite(RuntimeContext& runtime) {
    runListAndSearchSuite(runtime, true);
}

}  // namespace search_bench
