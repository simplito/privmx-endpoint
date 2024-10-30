#include "privmx/endpoint/core/Config.hpp"

#include <privmx/crypto/OpenSSLUtils.hpp>

using namespace privmx::endpoint::core;

void Config::setCertsPath(const std::string& certsPath) {
    crypto::OpenSSLUtils::CaLocation = certsPath;
}
