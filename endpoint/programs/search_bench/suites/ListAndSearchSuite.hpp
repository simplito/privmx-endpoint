#pragma once

#include "SearchBenchRuntime.hpp"

namespace search_bench {

void runListSuite(RuntimeContext& runtime);
void runSearchSuite(RuntimeContext& runtime);
void runListAndSearchSuite(RuntimeContext& runtime);
void runListAndSearchPreloadedSuite(RuntimeContext& runtime);

}  // namespace search_bench
