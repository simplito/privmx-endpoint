#include "privmx/endpoint/store/FileKeyIdFormatValidator.hpp"
#include "privmx/endpoint/store/StoreException.hpp"
using namespace privmx::endpoint::store;

void FileKeyIdFormatValidator::assertKeyIdFormat(const std::string& keyId) {
    if (!isKeyIdFormatValid(keyId)) {
        throw IncorrectKeyIdFormatException();
    }
}

bool FileKeyIdFormatValidator::isKeyIdFormatValid(const std::string& keyId) {
    return hasDefaultKeyIdFormat(keyId);
}
