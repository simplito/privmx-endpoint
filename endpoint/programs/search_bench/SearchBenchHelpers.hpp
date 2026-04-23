#pragma once

#include <privmx/endpoint/search/Types.hpp>

#include <string>
#include <vector>

namespace search_bench {

std::vector<std::string> readTextFileLines(const std::string& filePath);
std::vector<std::string> generateMessages(const std::vector<std::string>& words, int num);
std::string extractMessageDataFromJson(const std::string& json);
std::vector<privmx::endpoint::search::NewDocument> loadDocumentsFromJsonDirectory(
    const std::string& directoryPath,
    std::size_t maxDocuments
);
std::vector<privmx::endpoint::search::NewDocument> loadDocumentsFromRfcDirectory(
    const std::string& directoryPath,
    std::size_t maxDocuments
);

}  // namespace search_bench
