#include "SearchBenchProfiler.hpp"

#include <cerrno>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;

namespace search_bench {

namespace {

std::vector<char*> makeExecArguments(std::vector<std::string>& arguments) {
    std::vector<char*> execArguments;
    execArguments.reserve(arguments.size() + 1);

    for (auto& argument : arguments) {
        execArguments.push_back(argument.data());
    }
    execArguments.push_back(nullptr);

    return execArguments;
}

}  // namespace

PerfRunResult runWithPerfProfiler(const char* executablePath, const ProgramOptions& options) {
    auto outputDir = fs::absolute(options.profileOutDir);
    fs::create_directories(outputDir);

    auto outputBaseName = options.listMode ? std::string("list_search_indexes") : options.suiteName;
    auto perfDataPath = (outputDir / (outputBaseName + ".perf.data")).string();

    std::vector<std::string> arguments{
        "perf",
        "record",
        "-F",
        "999",
        "-g",
        "--call-graph",
        "dwarf,16384",
        "-o",
        perfDataPath,
        "--",
        executablePath,
    };

    auto childOptions = options;
    childOptions.profileMode = ProfileMode::None;
    auto childArguments = buildProgramArguments(childOptions);
    arguments.insert(arguments.end(), childArguments.begin(), childArguments.end());

    auto execArguments = makeExecArguments(arguments);

    auto pid = fork();
    if (pid < 0) {
        throw std::runtime_error("fork() failed: " + std::string(std::strerror(errno)));
    }

    if (pid == 0) {
        execvp("perf", execArguments.data());
        _exit(errno == ENOENT ? 127 : 126);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        throw std::runtime_error("waitpid() failed: " + std::string(std::strerror(errno)));
    }

    if (WIFEXITED(status)) {
        return {
            .exitCode = WEXITSTATUS(status),
            .perfDataPath = perfDataPath,
        };
    }

    if (WIFSIGNALED(status)) {
        return {
            .exitCode = 128 + WTERMSIG(status),
            .perfDataPath = perfDataPath,
        };
    }

    throw std::runtime_error("perf process terminated unexpectedly");
}

}  // namespace search_bench
