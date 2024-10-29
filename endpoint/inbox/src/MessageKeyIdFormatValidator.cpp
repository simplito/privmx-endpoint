#include "privmx/endpoint/inbox/MessageKeyIdFormatValidator.hpp"
#include "privmx/endpoint/inbox/InboxException.hpp"
#include <privmx/utils/Utils.hpp>
using namespace privmx::endpoint::inbox;

void MessageKeyIdFormatValidator::assertKeyIdFormat(const std::string& keyId) {
    if (!isKeyIdFormatValid(keyId)) {
        throw IncorrectKeyIdFormatException();
    }
}

bool MessageKeyIdFormatValidator::isKeyIdFormatValid(const std::string& keyId) {
    return hasExtendedKeyIdFormat(keyId, "inbox", 1);
}
