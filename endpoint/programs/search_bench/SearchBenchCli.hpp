#pragma once

#include <optional>
#include <ostream>
#include <string>
#include <vector>

namespace search_bench {

enum class ProfileMode {
    None,
    Perf,
};

struct ProgramOptions {
    bool listMode = false;
    ProfileMode profileMode = ProfileMode::None;
    std::string profileOutDir = "perf-output";
    std::string searchIndex;
    std::string suiteName;
    std::string privKey;
    std::string solutionId;
    std::string bridgeUrl;
    std::string contextId;
    std::string rfcDir;
    std::string messagesDir;
};

struct ParseResult {
    std::optional<ProgramOptions> options;
    bool helpRequested = false;
    std::optional<std::string> errorMessage;
};

ParseResult parseProgramOptions(int argc, char* argv[]);
void printUsage(std::ostream& output, const std::string& programName);
std::vector<std::string> buildProgramArguments(const ProgramOptions& options);
std::string profileModeToString(ProfileMode mode);

}  // namespace search_bench
