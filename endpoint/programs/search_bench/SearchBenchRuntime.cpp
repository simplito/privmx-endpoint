#include "SearchBenchRuntime.hpp"

#include <privmx/endpoint/core/Types.hpp>

#include <string_view>

namespace search_bench {

namespace {

constexpr int64_t kSearchIndexListLimit = 100;

std::string_view indexModeToString(privmx::endpoint::search::IndexMode mode) {
    switch (mode) {
        case privmx::endpoint::search::IndexMode::WITH_CONTENT:
            return "WITH_CONTENT";
        case privmx::endpoint::search::IndexMode::WITHOUT_CONTENT:
            return "WITHOUT_CONTENT";
    }

    return "UNKNOWN";
}

}  // namespace

RuntimeContext createRuntimeContext(const ProgramOptions& options) {
    auto connection = privmx::endpoint::core::Connection::connect(
        options.privKey,
        options.solutionId,
        options.bridgeUrl
    );

    auto kvdbApi = privmx::endpoint::kvdb::KvdbApi::create(connection);
    auto storeApi = privmx::endpoint::store::StoreApi::create(connection);
    auto searchApi = privmx::endpoint::search::SearchApi::create(connection, storeApi, kvdbApi);

    return RuntimeContext{
        .options = options,
        .connection = std::move(connection),
        .kvdbApi = std::move(kvdbApi),
        .storeApi = std::move(storeApi),
        .searchApi = std::move(searchApi),
    };
}

std::vector<privmx::endpoint::core::UserWithPubKey> getContextUsersWithPubKeys(RuntimeContext& runtime) {
    auto contextUsersInfo = runtime.connection.listContextUsers(runtime.options.contextId, {0, 100, "asc"});

    std::vector<privmx::endpoint::core::UserWithPubKey> usersWithPubKey;
    usersWithPubKey.reserve(contextUsersInfo.readItems.size());

    for (const auto& userInfo : contextUsersInfo.readItems) {
        usersWithPubKey.push_back(userInfo.user);
    }

    return usersWithPubKey;
}

void printSearchIndexes(RuntimeContext& runtime, std::ostream& output) {
    privmx::endpoint::core::PagingQuery pagingQuery{
        .skip = 0,
        .limit = kSearchIndexListLimit,
        .sortOrder = "desc",
    };

    auto indexes = runtime.searchApi.listSearchIndexes(runtime.options.contextId, pagingQuery);
    output << "Search indexes for context " << runtime.options.contextId << ": "
           << indexes.readItems.size() << " / " << indexes.totalAvailable << '\n';

    if (indexes.readItems.empty()) {
        output << "No search indexes found.\n";
        return;
    }

    for (const auto& index : indexes.readItems) {
        output << "- indexId: " << index.indexId
               << ", version: " << index.version
               << ", mode: " << indexModeToString(index.mode)
               << ", creator: " << index.creator
               << ", createDate: " << index.createDate
               << ", lastModifier: " << index.lastModifier
               << ", lastModificationDate: " << index.lastModificationDate
               << ", users: " << index.users.size()
               << ", managers: " << index.managers.size()
               << '\n';
    }
}

}  // namespace search_bench
