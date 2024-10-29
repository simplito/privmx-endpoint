#include "privmx/endpoint/inbox/InboxVarDeserializer.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

#include "privmx/endpoint/core/TypeValidator.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

template<>
inbox::FilesConfig VarDeserializer::deserialize<inbox::FilesConfig>(const Poco::Dynamic::Var& val,
                                                                    const std::string& name) {
    core::TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {.minCount = deserialize<int64_t>(obj->get("minCount"), name + ".minCount"),
            .maxCount = deserialize<int64_t>(obj->get("maxCount"), name + ".maxCount"),
            .maxFileSize = deserialize<int64_t>(obj->get("maxFileSize"), name + ".maxFileSize"),
            .maxWholeUploadSize = deserialize<int64_t>(obj->get("maxWholeUploadSize"), name + ".maxWholeUploadSize")};
}
