#pragma once

#include "SearchBenchRuntime.hpp"

#include <string_view>
#include <vector>

namespace search_bench {

enum class SuiteId {
    BatchAddAndSearch,
    BatchAdd1000,
    BatchAdd2000,
    BatchAdd3000,
    BatchAdd100k,
    ListAndSearch,
    ListAndSearchPreloaded,
    BatchAdd1000ToExisting,
    BatchAdd1000Rfcs,
};

struct SuiteDefinition {
    SuiteId id;
    const char* name;
    const char* description;
    void (*run)(RuntimeContext& runtime);
};

const std::vector<SuiteDefinition>& getSuiteDefinitions();
const SuiteDefinition* findSuiteDefinition(std::string_view suiteName);

}  // namespace search_bench
