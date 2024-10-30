

#include "privmx/endpoint/core/KeyIdFormatValidator.hpp"
#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/utils/Utils.hpp"

using namespace privmx::endpoint::core;

bool KeyIdFormatValidator::hasDefaultKeyIdFormat(const std::string& keyId) {
    return keyId.size() == 32 && keyId.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos;
}

bool KeyIdFormatValidator::hasExtendedKeyIdFormat(const std::string& keyId, const std::string& prefix, size_t dataElements) {
    if(keyId.size() >= 2 && keyId.front() == '<' && keyId.back() == '>') {
        std::string trimmedKeyId = keyId.substr(1, keyId.size() - 2);
        std::vector<std::string> keyData = utils::Utils::splitStringByCharacter(trimmedKeyId, '-');
        if(!prefix.empty()) {
            if(keyData[0] != prefix) {
                return false;
            }
            dataElements+=1;
        }
        if(keyData.size() != dataElements) {
            return false;
        }
    } else {
        return false;
    }
    return true;
}
