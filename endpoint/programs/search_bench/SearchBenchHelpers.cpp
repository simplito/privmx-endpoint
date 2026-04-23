#include "SearchBenchHelpers.hpp"

#include <privmx/utils/Utils.hpp>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <stdexcept>

namespace fs = std::filesystem;

namespace search_bench {

namespace {

std::vector<fs::path> collectRegularFilesFromDirectory(const std::string& directoryPath) {
    if (!fs::exists(directoryPath)) {
        throw std::runtime_error("Directory does not exist: " + directoryPath);
    }
    if (!fs::is_directory(directoryPath)) {
        throw std::runtime_error("Path is not a directory: " + directoryPath);
    }

    std::vector<fs::path> files;
    for (const auto& entry : fs::directory_iterator(directoryPath)) {
        if (entry.is_regular_file()) {
            files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end());
    return files;
}

std::string readWholeFile(const fs::path& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        throw std::runtime_error("Unable to open file: " + filePath.string());
    }

    std::ostringstream content;
    content << file.rdbuf();
    return content.str();
}

}  // namespace

std::vector<std::string> readTextFileLines(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        throw std::runtime_error("Unable to open file: " + filePath);
    }

    std::vector<std::string> lines;
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.empty()) {
            continue;
        }
        lines.push_back(line);
    }

    return lines;
}

std::vector<std::string> generateMessages(const std::vector<std::string>& words, int num) {
    if (words.empty()) {
        throw std::runtime_error("Words list cannot be empty");
    }
    if (num < 0) {
        throw std::runtime_error("Number of messages cannot be negative");
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> messageLengthDist(5, 20);
    std::uniform_int_distribution<std::size_t> wordIndexDist(0, words.size() - 1);

    std::vector<std::string> messages;
    messages.reserve(static_cast<std::size_t>(num));

    for (int i = 0; i < num; ++i) {
        const int messageLength = messageLengthDist(gen);
        std::ostringstream message;

        for (int j = 0; j < messageLength; ++j) {
            if (j > 0) {
                message << ' ';
            }
            message << words[wordIndexDist(gen)];
        }

        messages.push_back(message.str());
    }

    return messages;
}

std::string extractMessageDataFromJson(const std::string& json) {
    auto jsonObject = privmx::utils::Utils::parseJsonObject(json);
    if (!jsonObject->has("data")) {
        throw std::runtime_error("JSON does not contain 'data' field");
    }
    return jsonObject->getValue<std::string>("data");
}

std::vector<privmx::endpoint::search::NewDocument> loadDocumentsFromJsonDirectory(
    const std::string& directoryPath,
    std::size_t maxDocuments
) {
    const auto files = collectRegularFilesFromDirectory(directoryPath);

    std::vector<privmx::endpoint::search::NewDocument> documents;
    documents.reserve(std::min(maxDocuments, files.size()));

    std::size_t id = 1;
    for (const auto& filePath : files) {
        if (documents.size() >= maxDocuments) {
            break;
        }

        documents.push_back({
            .name = "name_" + std::to_string(id++),
            .content = extractMessageDataFromJson(readWholeFile(filePath)),
        });
    }

    return documents;
}

std::vector<privmx::endpoint::search::NewDocument> loadDocumentsFromRfcDirectory(
    const std::string& directoryPath,
    std::size_t maxDocuments
) {
    const auto files = collectRegularFilesFromDirectory(directoryPath);

    std::vector<privmx::endpoint::search::NewDocument> documents;
    documents.reserve(std::min(maxDocuments, files.size()));

    for (const auto& filePath : files) {
        if (documents.size() >= maxDocuments) {
            break;
        }

        documents.push_back({
            .name = filePath.filename().string(),
            .content = readWholeFile(filePath),
        });
    }

    return documents;
}

}  // namespace search_bench
