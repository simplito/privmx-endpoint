#pragma once

#include "SearchBenchCli.hpp"

#include <string>

namespace search_bench {

struct PerfRunResult {
    int exitCode = 0;
    std::string perfDataPath;
};

PerfRunResult runWithPerfProfiler(const char* executablePath, const ProgramOptions& options);

}  // namespace search_bench
