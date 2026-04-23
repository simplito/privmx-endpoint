#include "SearchBenchSuites.hpp"

#include "suites/BatchAddAndSearchSuite.hpp"
#include "suites/BatchAdd1000Suite.hpp"
#include "suites/BatchAdd100kSuite.hpp"
#include "suites/BatchAdd2000Suite.hpp"
#include "suites/BatchAdd3000Suite.hpp"
#include "suites/ListAndSearchSuite.hpp"
#include "suites/BatchAdd1000ToExistingSuite.hpp"
#include "suites/BatchAdd1000RfcsSuite.hpp"
namespace search_bench {

const std::vector<SuiteDefinition>& getSuiteDefinitions() {
    static const std::vector<SuiteDefinition> suites{
        {
            .id = SuiteId::BatchAddAndSearch,
            .name = "batch_add_and_search",
            .description = "Create an index, add a batch of documents and run a search query.",
            .run = &runBatchAddAndSearchSuite,
        },
        {
            .id = SuiteId::BatchAdd1000,
            .name = "batch_add_1000",
            .description = "Create an index, add a batch of documents and return the index id",
            .run = &runBatchAdd1000Suite,
        },
    {
        .id = SuiteId::BatchAdd100k,
        .name = "batch_add_100k",
        .description = "Create an index, add a batch of documents and return the index id",
        .run = &runBatchAdd100kSuite,
    },
    {
            .id = SuiteId::BatchAdd2000,
            .name = "batch_add_2000",
            .description = "Create an index, add a batch of documents and return the index id",
            .run = &runBatchAdd2000Suite,
        },
        {
            .id = SuiteId::BatchAdd3000,
            .name = "batch_add_3000",
            .description = "Create an index, add a batch of documents and return the index id",
            .run = &runBatchAdd3000Suite,
        },
        {
            .id = SuiteId::ListAndSearch,
            .name = "list_and_search",
            .description = "List an index and run a search query.",
            .run = &runListAndSearchSuite,
        },
        {
            .id = SuiteId::ListAndSearchPreloaded,
            .name = "list_and_search_preloaded",
            .description = "List an index and run a search query with full index preload.",
            .run = &runListAndSearchPreloadedSuite,
        },
{
    .id = SuiteId::BatchAdd1000ToExisting,
    .name = "batch_add_1000_to_existing",
    .description = "Add a batch of documents to existing index",
    .run = &runBatchAdd1000ToExistingSuite,
},
{
    .id = SuiteId::BatchAdd1000Rfcs,
    .name = "batch_add_1000_rfcs",
    .description = "Create an index, add a batch of RRC documents and return the index id",
    .run = &runBatchAdd1000RfcsSuite,
},
};

    return suites;
}

const SuiteDefinition* findSuiteDefinition(std::string_view suiteName) {
    for (const auto& suite : getSuiteDefinitions()) {
        if (suite.name == suiteName) {
            return &suite;
        }
    }

    return nullptr;
}

}  // namespace search_bench
