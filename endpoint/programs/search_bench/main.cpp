#include "SearchBenchCli.hpp"
#include "SearchBenchProfiler.hpp"
#include "SearchBenchRuntime.hpp"
#include "SearchBenchSuites.hpp"

#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/utils/PrivmxException.hpp>

#include <exception>
#include <filesystem>
#include <iostream>

int main(int argc, char** argv) {
    auto parseResult = search_bench::parseProgramOptions(argc, argv);
    if (parseResult.helpRequested) {
        search_bench::printUsage(std::cout, argv[0]);
        return 0;
    }
    if (!parseResult.options.has_value()) {
        if (parseResult.errorMessage.has_value()) {
            std::cerr << *parseResult.errorMessage << '\n';
        }
        search_bench::printUsage(std::cerr, argv[0]);
        return -1;
    }

    auto options = *parseResult.options;

    const search_bench::SuiteDefinition* suite = nullptr;
    if (!options.listMode) {
        suite = search_bench::findSuiteDefinition(options.suiteName);
        if (suite == nullptr) {
            std::cerr << "Unknown suite: " << options.suiteName << '\n';
            search_bench::printUsage(std::cerr, argv[0]);
            return -1;
        }
    }

    if (options.profileMode == search_bench::ProfileMode::Perf) {
        try {
            auto perfRunResult = search_bench::runWithPerfProfiler(argv[0], options);
            auto outputBaseName = options.listMode ? std::string("list_search_indexes") : options.suiteName;
            auto svgPath = (std::filesystem::absolute(options.profileOutDir) / (outputBaseName + ".svg")).string();
            if (perfRunResult.exitCode == 0) {
                std::cout << "Perf profile saved to: " << perfRunResult.perfDataPath << '\n';
                std::cout << "Next step: perf script -i " << perfRunResult.perfDataPath
                          << " | stackcollapse-perf.pl | flamegraph.pl > "
                          << svgPath << '\n';
            } else {
                std::cerr << "perf record exited with code " << perfRunResult.exitCode << '\n';
                if (std::filesystem::exists(perfRunResult.perfDataPath)) {
                    std::cerr << "Partial perf data may be available at: " << perfRunResult.perfDataPath << '\n';
                }
            }
            return perfRunResult.exitCode;
        } catch (const std::exception& e) {
            std::cerr << e.what() << '\n';
            return -1;
        }
    }

    try {
        auto runtime = search_bench::createRuntimeContext(options);
        if (options.listMode) {
            search_bench::printSearchIndexes(runtime, std::cout);
            return 0;
        }
        suite->run(runtime);
    } catch (const privmx::endpoint::core::Exception& e) {
        std::cerr << e.getFull() << '\n';
    } catch (const privmx::utils::PrivmxException& e) {
        std::cerr << e.what() << '\n';
        std::cerr << e.getData() << '\n';
        std::cerr << e.getCode() << '\n';
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
    } catch (...) {
        std::cerr << "Error\n";
    }

    return 0;
}
