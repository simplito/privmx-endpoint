#include "privmx/endpoint/thread/MessageKeyIdFormatValidator.hpp"
#include "privmx/endpoint/thread/ThreadException.hpp"
using namespace privmx::endpoint::thread;

void MessageKeyIdFormatValidator::assertKeyIdFormat(const std::string& keyId) {
    if (!isKeyIdFormatValid(keyId)) {
        throw IncorrectKeyIdFormatException();
    }
}

bool MessageKeyIdFormatValidator::isKeyIdFormatValid(const std::string& keyId) {
    return hasDefaultKeyIdFormat(keyId);
}
