#include "SearchBenchCli.hpp"

#include "SearchBenchSuites.hpp"

#include <optional>
#include <string_view>
#include <vector>

namespace search_bench {

namespace {

std::optional<ProfileMode> parseProfileMode(std::string_view value) {
    if (value == "none") {
        return ProfileMode::None;
    }
    if (value == "perf") {
        return ProfileMode::Perf;
    }

    return std::nullopt;
}

}  // namespace

ParseResult parseProgramOptions(int argc, char* argv[]) {
    ProgramOptions options;
    std::vector<std::string> positionalArguments;
    positionalArguments.reserve(7);

    for (int i = 1; i < argc; ++i) {
        std::string_view argument = argv[i];
        if (argument == "--help") {
            return {.helpRequested = true};
        }

        if (argument == "--list") {
            options.listMode = true;
            continue;
        }

        if (argument.rfind("--profile=", 0) == 0) {
            auto parsedMode = parseProfileMode(argument.substr(std::string_view("--profile=").size()));
            if (!parsedMode.has_value()) {
                return {.errorMessage = "Invalid value for --profile"};
            }
            options.profileMode = *parsedMode;
            continue;
        }

        if (argument == "--profile") {
            if (i + 1 >= argc) {
                return {.errorMessage = "Missing value for --profile"};
            }
            auto parsedMode = parseProfileMode(argv[++i]);
            if (!parsedMode.has_value()) {
                return {.errorMessage = "Invalid value for --profile"};
            }
            options.profileMode = *parsedMode;
            continue;
        }

        if (argument.rfind("--profile-out=", 0) == 0) {
            options.profileOutDir = std::string(argument.substr(std::string_view("--profile-out=").size()));
            continue;
        }

        if (argument == "--profile-out") {
            if (i + 1 >= argc) {
                return {.errorMessage = "Missing value for --profile-out"};
            }
            options.profileOutDir = argv[++i];
            continue;
        }

        if (argument.rfind("--search-index=", 0) == 0) {
            options.searchIndex = std::string(argument.substr(std::string_view("--search-index=").size()));
            continue;
        }

        if (argument == "--search-index") {
            if (i + 1 >= argc) {
                return {.errorMessage = "Missing value for --search-index"};
            }
            options.searchIndex = argv[++i];
            continue;
        }

        if (argument.rfind("--", 0) == 0) {
            return {.errorMessage = "Unknown option: " + std::string(argument)};
        }

        positionalArguments.emplace_back(argument);
    }

    if (options.listMode) {
        if (positionalArguments.size() == 4) {
            options.privKey = positionalArguments[0];
            options.solutionId = positionalArguments[1];
            options.bridgeUrl = positionalArguments[2];
            options.contextId = positionalArguments[3];
            return {
                .options = options,
            };
        }

        if (positionalArguments.size() == 7) {
            options.suiteName = positionalArguments[0];
            options.privKey = positionalArguments[1];
            options.solutionId = positionalArguments[2];
            options.bridgeUrl = positionalArguments[3];
            options.contextId = positionalArguments[4];
            options.rfcDir = positionalArguments[5];
            options.messagesDir = positionalArguments[6];
            return {
                .options = options,
            };
        }

        return {.errorMessage = "Invalid number of positional arguments for --list"};
    }

    if (positionalArguments.size() != 7) {
        return {.errorMessage = "Invalid number of positional arguments"};
    }

    options.suiteName = positionalArguments[0];
    options.privKey = positionalArguments[1];
    options.solutionId = positionalArguments[2];
    options.bridgeUrl = positionalArguments[3];
    options.contextId = positionalArguments[4];
    options.rfcDir = positionalArguments[5];
    options.messagesDir = positionalArguments[6];

    return {
        .options = options,
    };
}

void printUsage(std::ostream& output, const std::string& programName) {
    output << "Usage:\n";
    output << "  " << programName
           << " [--profile <none|perf>] [--profile-out <dir>] [--list]"
           << " <PrivKey> <SolutionId> <BridgeUrl> <ContextId>\n";
    output << "  " << programName
           << " [--profile <none|perf>] [--profile-out <dir>]"
           << " <suite> [--search-index <id>] <PrivKey> <SolutionId> <BridgeUrl> <ContextId> <rfc_dir_path> <messages_dir_path>\n";
    output << "General options:\n";
    output << "  --list                     Ignore suite execution and print search indexes only\n";
    output << "Suite options:\n";
    output << "  --search-index <id>        Optional search index id passed through to suite logic\n";
    output << "Profiling options:\n";
    output << "  --profile <none|perf>      Select profiling mode. Default: none\n";
    output << "  --profile-out <dir>        Directory for profiler output. Default: perf-output\n";
    output << "Available suites:\n";
    for (const auto& suite : getSuiteDefinitions()) {
        output << "  - " << suite.name << ": " << suite.description << '\n';
    }
}

std::vector<std::string> buildProgramArguments(const ProgramOptions& options) {
    if (options.listMode) {
        return {
            "--list",
            "--profile=" + profileModeToString(options.profileMode),
            "--profile-out=" + options.profileOutDir,
            options.privKey,
            options.solutionId,
            options.bridgeUrl,
            options.contextId,
        };
    }

    std::vector<std::string> arguments{
        "--profile=" + profileModeToString(options.profileMode),
        "--profile-out=" + options.profileOutDir,
        options.suiteName,
    };

    if (!options.searchIndex.empty()) {
        arguments.push_back("--search-index=" + options.searchIndex);
    }

    arguments.insert(
        arguments.end(),
        {
            options.privKey,
            options.solutionId,
            options.bridgeUrl,
            options.contextId,
            options.rfcDir,
            options.messagesDir,
        }
    );

    return arguments;
}

std::string profileModeToString(ProfileMode mode) {
    switch (mode) {
        case ProfileMode::None:
            return "none";
        case ProfileMode::Perf:
            return "perf";
    }

    return "none";
}

}  // namespace search_bench
