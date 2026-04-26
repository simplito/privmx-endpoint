#pragma once

#include "SearchBenchCli.hpp"

#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/kvdb/KvdbApi.hpp>
#include <privmx/endpoint/search/SearchApi.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>

#include <ostream>
#include <vector>

namespace search_bench {

struct RuntimeContext {
    ProgramOptions options;
    privmx::endpoint::core::Connection connection;
    privmx::endpoint::kvdb::KvdbApi kvdbApi;
    privmx::endpoint::store::StoreApi storeApi;
    privmx::endpoint::search::SearchApi searchApi;

    int64_t getSearchIndexSize(const std::string& searchIndexId);
};

RuntimeContext createRuntimeContext(const ProgramOptions& options);
std::vector<privmx::endpoint::core::UserWithPubKey> getContextUsersWithPubKeys(RuntimeContext& runtime);
void printSearchIndexes(RuntimeContext& runtime, std::ostream& output);

}  // namespace search_bench
