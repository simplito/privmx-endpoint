#include "privmx/endpoint/core/varinterface/VarInterfaceUtil.hpp"

#include "privmx/endpoint/core/CoreException.hpp"

using namespace privmx::endpoint::core;
Poco::JSON::Array::Ptr VarInterfaceUtil::validateAndExtractArray(const Poco::Dynamic::Var& args, std::size_t size) {
    return validateAndExtractArray(args, size, size);
}

Poco::JSON::Array::Ptr VarInterfaceUtil::validateAndExtractArray(const Poco::Dynamic::Var& args, std::size_t minSize,
                                                                 std::size_t maxSize) {
    Poco::JSON::Array::Ptr arr = args.extract<Poco::JSON::Array::Ptr>();
    if (arr->size() < minSize || arr->size() > maxSize) {
        throw core::InvalidNumberOfParamsException();
    }
    return arr;
}
