#include "privmx/endpoint/inbox/FileKeyIdFormatValidator.hpp"
#include "privmx/endpoint/inbox/InboxException.hpp"
using namespace privmx::endpoint::inbox;

void FileKeyIdFormatValidator::assertKeyIdFormat(const std::string& keyId) {
    if (!isKeyIdFormatValid(keyId)) {
        throw IncorrectKeyIdFormatException();
    }
}

bool FileKeyIdFormatValidator::isKeyIdFormatValid(const std::string& keyId) {
    return hasExtendedKeyIdFormat(keyId, "inboxmsg", 3);
}
