#include <privmx/rpc/RpcUtils.hpp>

using namespace privmx::rpc;

const std::regex RpcUtils::HOSTNAME_REGEX{"^(([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9-_]*[a-zA-Z0-9_]).)*([A-Za-z0-9_]|[A-Za-z0-9_][A-Za-z0-9-_]*[A-Za-z0-9_])$"};

bool RpcUtils::isValidHostname(const std::string& hostname) {
    return std::regex_match(hostname, HOSTNAME_REGEX);
}
